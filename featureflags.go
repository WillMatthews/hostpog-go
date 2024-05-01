package posthog

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const LONG_SCALE = 0xfffffffffffffff

type FeatureFlagsPoller struct {
	loaded         chan bool
	shutdown       chan bool
	forceReload    chan bool
	featureFlags   []FeatureFlag
	cohorts        map[string]PropertyGroup
	groups         map[string]string
	personalApiKey string
	projectApiKey  string
	Errorf         func(format string, args ...interface{})
	Endpoint       string
	http           http.Client
	mutex          sync.RWMutex
	nextPollTick   func() time.Duration
	flagTimeout    time.Duration
}

type FeatureFlag struct {
	Key                        string `json:"key"`
	IsSimpleFlag               bool   `json:"is_simple_flag"`
	RolloutPercentage          *uint8 `json:"rollout_percentage"`
	Active                     bool   `json:"active"`
	Filters                    Filter `json:"filters"`
	EnsureExperienceContinuity *bool  `json:"ensure_experience_continuity"`
}

type Filter struct {
	AggregationGroupTypeIndex *uint8                 `json:"aggregation_group_type_index"`
	Groups                    []FeatureFlagCondition `json:"groups"`
	Multivariate              *Variants              `json:"multivariate"`
}

type Variants struct {
	Variants []FlagVariant `json:"variants"`
}

type FlagVariant struct {
	Key               string `json:"key"`
	Name              string `json:"name"`
	RolloutPercentage *uint8 `json:"rollout_percentage"`
}

type FeatureFlagCondition struct {
	Properties        []FlagProperty `json:"properties"`
	RolloutPercentage *uint8         `json:"rollout_percentage"`
	Variant           *string        `json:"variant"`
}

type FlagProperty struct {
	Key      string      `json:"key"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"` // what the fuck is this? is it a PropValue or is it a FlagValue?
	Type     string      `json:"type"`
	Negation bool        `json:"negation"`
}

type FlagValue interface {
	_hydra()
	truthy() bool
}

type FlagValueSimple bool
type FlagValueString string

func (FlagValueSimple) _hydra() {}
func (FlagValueString) _hydra() {}

func (s FlagValueSimple) truthy() bool {
	return bool(s)
}

func (f FlagValueString) truthy() bool {
	return len(f) > 0 // maybe?
}

// PropValue may be a PropertyGroup or a FlagProperty (union type)
// ARRRGH THIS IS RECURSIVELY DEFINED??
type PropValue interface {
	_isValue()
}

func (PropertyGroup) _isValue() {}
func (FlagProperty) _isValue()  {}

type PropertyGroup struct {
	Type   string      `json:"type"`
	Values []PropValue `json:"values"`
}

type FlagVariantMeta struct {
	ValueMin float64
	ValueMax float64
	Key      string
}

type FeatureFlagsResponse struct {
	Flags            []FeatureFlag            `json:"flags"`
	GroupTypeMapping *map[string]string       `json:"group_type_mapping"`
	Cohorts          map[string]PropertyGroup `json:"cohorts"`
}

type DecideRequestData struct {
	ApiKey           string                `json:"api_key"`
	DistinctId       string                `json:"distinct_id"`
	Groups           Groups                `json:"groups"`
	PersonProperties Properties            `json:"person_properties"`
	GroupProperties  map[string]Properties `json:"group_properties"`
}

type DecideResponse struct {
	FeatureFlags flagz `json:"featureFlags"`
}

type flagz map[string]interface{}

type InconclusiveMatchError struct {
	msg string
}

func (e *InconclusiveMatchError) Error() string {
	return e.msg
}

func newFeatureFlagsPoller(
	projectApiKey string,
	personalApiKey string,
	errorf func(format string, args ...interface{}),
	endpoint string,
	httpClient http.Client,
	pollingInterval time.Duration,
	nextPollTick func() time.Duration,
	flagTimeout time.Duration,
) *FeatureFlagsPoller {

	if nextPollTick == nil {
		nextPollTick = func() time.Duration { return pollingInterval }
	}

	poller := FeatureFlagsPoller{
		loaded:         make(chan bool),
		shutdown:       make(chan bool),
		forceReload:    make(chan bool),
		personalApiKey: personalApiKey,
		projectApiKey:  projectApiKey,
		Errorf:         errorf,
		Endpoint:       endpoint,
		http:           httpClient,
		mutex:          sync.RWMutex{},
		nextPollTick:   nextPollTick,
		flagTimeout:    flagTimeout,
	}

	go poller.run()
	return &poller
}

func (poller *FeatureFlagsPoller) run() {
	poller.fetchNewFeatureFlags()
	close(poller.loaded)

	for {
		timer := time.NewTimer(poller.nextPollTick())
		select {
		case <-poller.shutdown:
			close(poller.shutdown)
			close(poller.forceReload)
			timer.Stop()
			return
		case <-poller.forceReload:
			timer.Stop()
			poller.fetchNewFeatureFlags()
		case <-timer.C:
			poller.fetchNewFeatureFlags()
		}
	}
}

func (poller *FeatureFlagsPoller) fetchNewFeatureFlags() {
	personalApiKey := poller.personalApiKey
	headers := [][2]string{{"Authorization", "Bearer " + personalApiKey + ""}}
	res, cancel, err := poller.localEvaluationFlags(headers)
	defer cancel()
	if err != nil || res.StatusCode != http.StatusOK {
		poller.Errorf("Unable to fetch feature flags", err)
		return
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		poller.Errorf("Unable to fetch feature flags", err)
		return
	}
	featureFlagsResponse := FeatureFlagsResponse{}
	err = json.Unmarshal([]byte(resBody), &featureFlagsResponse)
	if err != nil {
		poller.Errorf("Unable to unmarshal response from api/feature_flag/local_evaluation", err)
		return
	}
	newFlags := []FeatureFlag{}
	newFlags = append(newFlags, featureFlagsResponse.Flags...)
	poller.mutex.Lock()
	poller.featureFlags = newFlags
	poller.cohorts = featureFlagsResponse.Cohorts
	if featureFlagsResponse.GroupTypeMapping != nil {
		poller.groups = *featureFlagsResponse.GroupTypeMapping
	}
	poller.mutex.Unlock()
}

func (poller *FeatureFlagsPoller) GetFeatureFlag(
	flagConfig FeatureFlagPayload,
) (FlagValue, error) {
	featureFlags, err := poller.GetFeatureFlags()
	if err != nil {
		return nil, err
	}
	cohorts := poller.cohorts

	featureFlag := FeatureFlag{Key: ""}

	// avoid using flag for conflicts with Golang's stdlib `flag`
	for _, storedFlag := range featureFlags {
		if flagConfig.Key == storedFlag.Key {
			featureFlag = storedFlag
			break
		}
	}

	// I'll come to this after shooting myself in the head
	var result FlagValue

	if featureFlag.Key != "" {
		result, err = poller.computeFlagLocally(
			featureFlag,
			flagConfig.DistinctId,
			flagConfig.Groups,
			flagConfig.PersonProperties,
			flagConfig.GroupProperties,
			cohorts,
		)
	}

	if err != nil {
		poller.Errorf("Unable to compute flag locally (%s) - %s", featureFlag.Key, err)
	}

	if (err != nil || result == nil) && !flagConfig.OnlyEvaluateLocally {

		result, err = poller.getFeatureFlagVariant(
			featureFlag,
			flagConfig.Key,
			flagConfig.DistinctId,
			flagConfig.Groups,
			flagConfig.PersonProperties,
			flagConfig.GroupProperties,
		)
		if err != nil {
			return nil, err
		}
	}

	return result, err
}

func (poller *FeatureFlagsPoller) GetAllFlags(
	flagConfig FeatureFlagPayloadNoKey,
) (map[string]interface{}, error) {
	response := map[string]interface{}{}
	featureFlags, err := poller.GetFeatureFlags()
	if err != nil {
		return nil, err
	}
	fallbackToDecide := false
	cohorts := poller.cohorts

	if len(featureFlags) == 0 {
		fallbackToDecide = true
	} else {
		for _, storedFlag := range featureFlags {
			result, err := poller.computeFlagLocally(
				storedFlag,
				flagConfig.DistinctId,
				flagConfig.Groups,
				flagConfig.PersonProperties,
				flagConfig.GroupProperties,
				cohorts,
			)
			if err != nil {
				poller.Errorf("Unable to compute flag locally (%s) - %s", storedFlag.Key, err)
				fallbackToDecide = true
			} else {
				response[storedFlag.Key] = result
			}
		}
	}

	if fallbackToDecide && !flagConfig.OnlyEvaluateLocally {
		result, err := poller.getFeatureFlagVariants(
			flagConfig.DistinctId,
			flagConfig.Groups,
			flagConfig.PersonProperties,
			flagConfig.GroupProperties,
		)

		if err != nil {
			return response, err
		} else {
			for k, v := range result {
				response[k] = v
			}
		}
	}

	return response, nil
}

func (poller *FeatureFlagsPoller) computeFlagLocally(
	flag FeatureFlag,
	distinctId string,
	groups Groups,
	personProperties Properties,
	groupProperties map[string]Properties,
	cohorts map[string]PropertyGroup,
) (FlagValue, error) {
	if flag.EnsureExperienceContinuity != nil && *flag.EnsureExperienceContinuity {
		return nil, &InconclusiveMatchError{"Flag has experience continuity enabled"}
	}

	if !flag.Active {
		return FlagValueSimple(false), nil
	}

	if flag.Filters.AggregationGroupTypeIndex != nil {
		groupName, exists := poller.groups[fmt.Sprintf("%d", *flag.Filters.AggregationGroupTypeIndex)]
		if !exists {
			return nil, errors.New("Flag has unknown group type index")
		}

		_, exists = groups[groupName]
		if !exists {
			errMessage := fmt.Sprintf(
				"FEATURE FLAGS] Can't compute group feature flag: %s without group names passed in",
				flag.Key,
			)
			return nil, errors.New(errMessage)
		}

		focusedGroupProperties := groupProperties[groupName]
		return matchFeatureFlagProperties(
			flag,
			groups[groupName].(string),
			focusedGroupProperties,
			cohorts,
		)
	}

	return matchFeatureFlagProperties(flag, distinctId, personProperties, cohorts)

}

func getMatchingVariant(flag FeatureFlag, distinctId string) (FlagValue, error) {
	lookupTable := getVariantLookupTable(flag)
	hashValue, err := _hash(flag.Key, distinctId, "variant")
	if err != nil {
		return nil, err
	}

	for _, variant := range lookupTable {
		if hashValue >= float64(variant.ValueMin) && hashValue < float64(variant.ValueMax) {
			return FlagValueString(variant.Key), nil
		}
	}
	return FlagValueSimple(true), nil
}

func getVariantLookupTable(flag FeatureFlag) []FlagVariantMeta {
	lookupTable := []FlagVariantMeta{}
	valueMin := 0.00

	multivariates := flag.Filters.Multivariate

	if multivariates == nil || multivariates.Variants == nil {
		return lookupTable
	}

	for _, variant := range multivariates.Variants {
		valueMax := float64(valueMin) + float64(*variant.RolloutPercentage)/100
		_flagVariantMeta := FlagVariantMeta{
			ValueMin: float64(valueMin),
			ValueMax: valueMax,
			Key:      variant.Key,
		}
		lookupTable = append(lookupTable, _flagVariantMeta)
		valueMin = float64(valueMax)
	}
	return lookupTable
}

func matchFeatureFlagProperties(
	flag FeatureFlag,
	distinctId string,
	properties Properties,
	cohorts map[string]PropertyGroup,
) (FlagValue, error) {
	conditions := flag.Filters.Groups
	isInconclusive := false

	// # Stable sort conditions with variant overrides to the top. This ensures that if overrides are present, they are
	// # evaluated first, and the variant override is applied to the first matching condition.
	// conditionsCopy := make([]PropertyGroup, len(conditions))
	sortedConditions := append([]FeatureFlagCondition{}, conditions...)

	sort.SliceStable(sortedConditions, func(i, j int) bool {
		iValue := 1
		jValue := 1
		if sortedConditions[i].Variant != nil {
			iValue = -1
		}

		if sortedConditions[j].Variant != nil {
			jValue = -1
		}

		return iValue < jValue
	})

	for _, condition := range sortedConditions {

		isMatch, err := isConditionMatch(flag, distinctId, condition, properties, cohorts)
		if err != nil {
			if _, ok := err.(*InconclusiveMatchError); ok {
				isInconclusive = true
			} else {
				return nil, err
			}
		}

		if isMatch {
			variantOverride := condition.Variant
			multivariates := flag.Filters.Multivariate

			if variantOverride != nil && multivariates != nil && multivariates.Variants != nil &&
				containsVariant(multivariates.Variants, *variantOverride) {
				return FlagValueString(*variantOverride), nil
			} else {
				return getMatchingVariant(flag, distinctId)
			}
		}
	}

	if isInconclusive {
		return FlagValueSimple(false), &InconclusiveMatchError{
			"Can't determine if feature flag is enabled or not with given properties",
		}
	}
	return FlagValueSimple(false), nil
}

// This function is OK
func isConditionMatch(
	flag FeatureFlag,
	distinctId string,
	condition FeatureFlagCondition,
	properties Properties,
	cohorts map[string]PropertyGroup,
) (bool, error) {
	if len(condition.Properties) > 0 {
		for _, prop := range condition.Properties {
			var isMatch bool
			var err error

			if prop.Type == "cohort" {
				isMatch, err = matchCohort(prop, properties, cohorts)
			} else {
				isMatch, err = matchProperty(prop, properties)
			}
			if err != nil {
				return false, err
			}
			if !isMatch {
				return isMatch, nil
			}
		}

		if condition.RolloutPercentage != nil {
			return true, nil
		}
	}

	if condition.RolloutPercentage != nil {
		return checkIfSimpleFlagEnabled(flag.Key, distinctId, *condition.RolloutPercentage)
	}
	return true, nil
}

// this function is OK
func matchCohort(
	property FlagProperty,
	properties Properties,
	cohorts map[string]PropertyGroup,
) (bool, error) {
	cohortId := fmt.Sprint(property.Value)
	propertyGroup, ok := cohorts[cohortId]
	if !ok {
		return false, fmt.Errorf("Can't match cohort: cohort %s not found", cohortId)
	}
	return matchPropertyGroup(propertyGroup, properties, cohorts)
}

// come back to look at this. Seems ok, but warrants more attention
func matchPropertyGroup(
	propertyGroup PropertyGroup,
	properties Properties,
	cohorts map[string]PropertyGroup,
) (bool, error) {
	groupType := propertyGroup.Type

	if len(propertyGroup.Values) == 0 {
		// empty groups are no-ops, always match
		return true, nil
	}

	errorMatchingLocally := false

	for _, value := range propertyGroup.Values {
		switch prop := value.(type) {
		case PropertyGroup:
			if len(prop.Values) > 0 {
				matches, err := matchPropertyGroup(prop, properties, cohorts)
				if err != nil {
					if _, ok := err.(*InconclusiveMatchError); ok {
						errorMatchingLocally = true
					} else {
						return false, err
					}
				}

				if groupType == "AND" {
					if !matches {
						return matches, nil
					}
				} else { // OR group
					if matches {
						return matches, nil
					}
				}
			}
		case FlagProperty:
			var matches bool
			var err error
			if prop.Type == "cohort" {
				matches, err = matchCohort(prop, properties, cohorts)
			} else {
				matches, err = matchProperty(prop, properties)
			}
			if err != nil {
				if _, ok := err.(*InconclusiveMatchError); ok {
					errorMatchingLocally = true
				} else {
					return false, err
				}
			}

			negation := prop.Negation
			andTest := !matches && !negation || matches && negation
			orTest := matches && !negation || !matches && negation
			if groupType == "AND" {
				if andTest {
					return false, nil
				}
			} else {
				if orTest {
					return true, nil
				}
			}

		default:
			return false, errors.New("Unknown property type")
		}
	}

	if errorMatchingLocally {
		return false, &InconclusiveMatchError{
			msg: "Can't match cohort without a given cohort property value",
		}
	}

	// if we get here, all matched in AND case, or none matched in OR case
	return groupType == "AND", nil
}

// should properties be []value instead?
func matchProperty(property FlagProperty, properties Properties) (bool, error) {
	key := property.Key
	operator := property.Operator
	value := property.Value
	if _, ok := properties[key]; !ok {
		return false, &InconclusiveMatchError{
			"Can't match properties without a given property value",
		}
	}

	if operator == "is_not_set" {
		return false, &InconclusiveMatchError{"Can't match properties with operator is_not_set"}
	}

	// idk what override_value does. it scares the shit out of me.
	override_value, _ := properties[key]

	if operator == "exact" {
		switch t := value.(type) {
		case []interface{}:
			return contains(t, override_value), nil
		default:
			return value == override_value, nil
		}
	}

	if operator == "is_not" {
		switch t := value.(type) {
		case []interface{}:
			return !contains(t, override_value), nil
		default:
			return value != override_value, nil
		}
	}

	if operator == "is_set" {
		return true, nil
	}

	if operator == "icontains" {
		return strings.Contains(
			strings.ToLower(fmt.Sprintf("%v", override_value)),
			strings.ToLower(fmt.Sprintf("%v", value)),
		), nil
	}

	if operator == "not_icontains" {
		return !strings.Contains(
			strings.ToLower(fmt.Sprintf("%v", override_value)),
			strings.ToLower(fmt.Sprintf("%v", value)),
		), nil
	}

	if operator == "regex" {
		r, err := regexp.Compile(fmt.Sprintf("%v", value))
		// invalid regex
		if err != nil {
			return false, nil // WHY??? Why why why????
		}

		match := r.MatchString(fmt.Sprintf("%v", override_value))
		return match, nil
	}

	if operator == "not_regex" {
		var r *regexp.Regexp
		var err error

		if valueString, ok := value.(string); ok {
			r, err = regexp.Compile(valueString)
		} else if valueInt, ok := value.(int); ok {
			valueString = strconv.Itoa(valueInt)
			r, err = regexp.Compile(valueString)
		} else {
			return false, errors.New("Regex expression not allowed")
		}

		// invalid regex
		if err != nil {
			return false, nil // WHY??? Why why why???? Why not return an error?!
		}

		var match bool
		if valueString, ok := override_value.(string); ok {
			match = r.MatchString(valueString)
		} else if valueInt, ok := override_value.(int); ok {
			valueString = strconv.Itoa(valueInt)
			match = r.MatchString(valueString)
		} else {
			return false, errors.New("Value type not supported")
		}

		return !match, nil
	}

	var overrideValueFloat float64
	operatorIsMathematical := operator == "gt" || operator == "lt" || operator == "gte" ||
		operator == "lte"
	if operatorIsMathematical {
		var err error
		overrideValueFloat, err = interfaceToFloat(override_value)
		if err != nil {
			return false, err
		}
	}

	if operator == "gt" {
		valueOrderable, err := interfaceToFloat(value)
		if err != nil {
			return false, err
		}

		return overrideValueFloat > valueOrderable, nil
	}

	if operator == "lt" {
		valueOrderable, err := interfaceToFloat(value)
		if err != nil {
			return false, err
		}

		return overrideValueFloat < valueOrderable, nil
	}

	if operator == "gte" {
		valueOrderable, err := interfaceToFloat(value)
		if err != nil {
			return false, err
		}

		return overrideValueFloat >= valueOrderable, nil
	}

	if operator == "lte" {
		valueOrderable, err := interfaceToFloat(value)
		if err != nil {
			return false, err
		}

		return overrideValueFloat <= valueOrderable, nil
	}

	return false, &InconclusiveMatchError{"Unknown operator: " + operator}

}

// WHY IS THIS A THING!!!!!
func interfaceToFloat(val interface{}) (float64, error) {
	var i float64
	switch t := val.(type) {
	case int:
		i = float64(t)
	case int8:
		i = float64(t)
	case int16:
		i = float64(t)
	case int32:
		i = float64(t)
	case int64:
		i = float64(t)
	case float32:
		i = float64(t)
	case float64:
		i = float64(t)
	case uint8:
		i = float64(t)
	case uint16:
		i = float64(t)
	case uint32:
		i = float64(t)
	case uint64:
		i = float64(t)
	default:
		errMessage := "argument not orderable"
		return 0.0, errors.New(errMessage)
	}

	return i, nil
}

func contains(s []interface{}, e interface{}) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func containsVariant(variantList []FlagVariant, key string) bool {
	for _, variant := range variantList {
		if variant.Key == key {
			return true
		}
	}
	return false
}

func (poller *FeatureFlagsPoller) isSimpleFlagEnabled(
	key string,
	distinctId string,
	rolloutPercentage uint8,
) (FlagValueSimple, error) {
	isEnabled, err := checkIfSimpleFlagEnabled(key, distinctId, rolloutPercentage)
	if err != nil {
		errMessage := "Error converting string to int"
		poller.Errorf(errMessage)
		return false, errors.New(errMessage)
	}
	return FlagValueSimple(isEnabled), nil
}

// extracted as a regular func for testing purposes
func checkIfSimpleFlagEnabled(
	key string,
	distinctId string,
	rolloutPercentage uint8,
) (bool, error) {
	val, err := _hash(key, distinctId, "")
	if err != nil {
		return false, err
	}

	return val <= float64(rolloutPercentage)/100, nil
}

func _hash(key string, distinctId string, salt string) (float64, error) {
	hash := sha1.New()
	hash.Write([]byte("" + key + "." + distinctId + "" + salt))
	digest := hash.Sum(nil)
	hexString := fmt.Sprintf("%x\n", digest)[:15]

	value, err := strconv.ParseInt(hexString, 16, 64)
	if err != nil {
		return 0, err
	}

	return float64(value) / LONG_SCALE, nil
}

func (poller *FeatureFlagsPoller) GetFeatureFlags() ([]FeatureFlag, error) {
	// When channel is open this will block. When channel is closed it will immediately exit.
	_, closed := <-poller.loaded
	if closed && poller.featureFlags == nil {
		// There was an error with initial flag fetching
		return nil, fmt.Errorf("Flags were not successfully fetched yet")
	}

	return poller.featureFlags, nil
}

func (poller *FeatureFlagsPoller) decide(
	requestData []byte,
	headers [][2]string,
) (*http.Response, context.CancelFunc, error) {
	decideEndpoint := "decide/?v=2"

	url, err := url.Parse(poller.Endpoint + "/" + decideEndpoint + "")
	if err != nil {
		poller.Errorf("creating url - %s", err)
	}

	return poller.request("POST", url, requestData, headers, poller.flagTimeout)
}

func (poller *FeatureFlagsPoller) localEvaluationFlags(
	headers [][2]string,
) (*http.Response, context.CancelFunc, error) {
	localEvaluationEndpoint := "api/feature_flag/local_evaluation"

	url, err := url.Parse(poller.Endpoint + "/" + localEvaluationEndpoint + "")
	if err != nil {
		poller.Errorf("creating url - %s", err)
	}
	searchParams := url.Query()
	searchParams.Add("token", poller.projectApiKey)
	searchParams.Add("send_cohorts", "true")
	url.RawQuery = searchParams.Encode()

	return poller.request("GET", url, []byte{}, headers, time.Duration(10)*time.Second)
}

func (poller *FeatureFlagsPoller) request(
	method string,
	url *url.URL,
	requestData []byte,
	headers [][2]string,
	timeout time.Duration,
) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	req, err := http.NewRequestWithContext(ctx, method, url.String(), bytes.NewReader(requestData))
	if err != nil {
		poller.Errorf("creating request - %s", err)
	}

	req.Header.Add("User-Agent", "posthog-go (version: "+getVersion()+")")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", fmt.Sprintf("%d", len(requestData)))

	for _, header := range headers {
		req.Header.Add(header[0], header[1])
	}

	res, err := poller.http.Do(req)
	if err != nil {
		poller.Errorf("sending request - %s", err)
	}

	return res, cancel, err
}

func (poller *FeatureFlagsPoller) ForceReload() {
	poller.forceReload <- true
}

func (poller *FeatureFlagsPoller) shutdownPoller() {
	poller.shutdown <- true
}

func (poller *FeatureFlagsPoller) getFeatureFlagVariants(
	distinctId string,
	groups Groups,
	personProperties Properties,
	groupProperties map[string]Properties,
) (flagz, error) {
	errorMessage := "Failed when getting flag variants"
	requestDataBytes, err := json.Marshal(DecideRequestData{
		ApiKey:           poller.projectApiKey,
		DistinctId:       distinctId,
		Groups:           groups,
		PersonProperties: personProperties,
		GroupProperties:  groupProperties,
	})
	if err != nil {
		errorMessage = "unable to marshal decide endpoint request data"
		poller.Errorf(errorMessage)
		return nil, errors.New(errorMessage)
	}

	headers := [][2]string{{"Authorization", "Bearer " + poller.personalApiKey + ""}}
	res, cancel, err := poller.decide(requestDataBytes, headers)
	defer cancel()
	if err != nil || res.StatusCode != http.StatusOK {
		errorMessage = "Error calling /decide/"
		if err != nil {
			errorMessage += " - " + err.Error()
		}
		poller.Errorf(errorMessage)
		return nil, errors.New(errorMessage)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		errorMessage = "Error reading response from /decide/"
		poller.Errorf(errorMessage)
		return nil, errors.New(errorMessage)
	}

	defer res.Body.Close()
	decideResponse := DecideResponse{}
	err = json.Unmarshal([]byte(resBody), &decideResponse)
	if err != nil {
		errorMessage = "Error parsing response from /decide/"
		poller.Errorf(errorMessage)
		return nil, errors.New(errorMessage)
	}

	return decideResponse.FeatureFlags, nil
}

func (poller *FeatureFlagsPoller) getFeatureFlagVariant(
	featureFlag FeatureFlag,
	key string,
	distinctId string,
	groups Groups,
	personProperties Properties,
	groupProperties map[string]Properties,
) (FlagValue, error) {

	if featureFlag.IsSimpleFlag {
		// json.Unmarshal will convert JSON `null` to a nullish value for each type
		// which is 0 for uint. However, our feature flags should have rolloutPercentage == 100
		// if it is set to `null`. Having rollout percentage be a pointer and deferencing it
		// here allows its value to be `nil` following json.Unmarhsal, so we can appropriately
		// set it to 100
		rolloutPercentage := uint8(100)
		if featureFlag.RolloutPercentage != nil {
			rolloutPercentage = *featureFlag.RolloutPercentage
		}
		result, err := poller.isSimpleFlagEnabled(key, distinctId, rolloutPercentage)
		if err != nil {
			return nil, err
		}
		return result, nil

	} else { // if not simple it should be multivariate! ... right?
		featureFlagVariants, variantErr := poller.getFeatureFlagVariants(distinctId, groups, personProperties, groupProperties)
		if variantErr != nil {
			return nil, variantErr
		}

		for flagKey, flagValue := range featureFlagVariants {
			flagValueString := fmt.Sprintf("%v", flagValue)
			if key == flagKey && flagValueString != "false" {
				result := FlagValueString(flagValueString)
				return result, nil
			}
		}
	}
	return nil, errors.New("Flag not found") // wam addition
}
