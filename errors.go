package liverunner

import (
	"errors"
	"fmt"
)

// ErrOrchestratorURLChanged reports a heartbeat response that tried to change
// the orchestrator URL while Options.PinOrchestratorURL is set.
var ErrOrchestratorURLChanged = errors.New("heartbeat response changed pinned orchestrator URL")

type HTTPError struct {
	StatusCode int
	URL        string
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("live runner HTTP error: status=%d url=%s body=%q", e.StatusCode, e.URL, e.Body)
}
