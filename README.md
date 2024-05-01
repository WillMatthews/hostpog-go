# HostPog Go

I had a small episode due to some of the limitations of Posthog-go.
I thought I'd channel my frustration into a _meaningful contribution to open source_ instead.

This repo aims to fix some of the problems I noticed with the original posthog repo:
- poor code quality
- love of interface{} (who needs typs anyway yee haw)
- lack of ability to use payloads

This is a work in progress, but I'll try to get somewhere, and maybe even open up a PR into posthog.


Please see the main [PostHog docs](https://posthog.com/docs).

Specifically, the [Go integration](https://posthog.com/docs/integrations/go-integration) details.

# Quickstart

Install posthog to your gopath
```bash
$ go get github.com/posthog/posthog-go
```

Go 🦔!
```go
package main

import (
    "os"
    "github.com/posthog/posthog-go"
)

func main() {
    client := posthog.New(os.Getenv("POSTHOG_API_KEY"))
    defer client.Close()

    // Capture an event
    client.Enqueue(posthog.Capture{
      DistinctId: "test-user",
      Event:      "test-snippet",
      Properties: posthog.NewProperties().
        Set("plan", "Enterprise").
        Set("friends", 42),
    })
    
    // Add context for a user
    client.Enqueue(posthog.Identify{
      DistinctId: "user:123",
      Properties: posthog.NewProperties().
        Set("email", "john@doe.com").
        Set("proUser", false),
    })
    
    // Link user contexts
    client.Enqueue(posthog.Alias{
      DistinctId: "user:123",
      Alias: "user:12345",
    })
    
    // Capture a pageview
    client.Enqueue(posthog.Capture{
      DistinctId: "test-user",
      Event:      "$pageview",
      Properties: posthog.NewProperties().
        Set("$current_url", "https://example.com"),
    })
}

```

## Questions?

### [Join our Slack community.](https://join.slack.com/t/posthogusers/shared_invite/enQtOTY0MzU5NjAwMDY3LTc2MWQ0OTZlNjhkODk3ZDI3NDVjMDE1YjgxY2I4ZjI4MzJhZmVmNjJkN2NmMGJmMzc2N2U3Yjc3ZjI5NGFlZDQ)
