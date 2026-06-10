package scan

import (
	"fmt"
	"strings"
	"time"
)

// OOBWaitTimeout is how long the out-of-band check waits for a callback after
// sending its payloads, per insertion point.
var OOBWaitTimeout = 4 * time.Second

// oobPollInterval is the cadence for polling the collaborator for interactions.
var oobPollInterval = 250 * time.Millisecond

// oobInjectionCheck detects blind vulnerabilities (SSRF, blind command/template
// injection, XXE) by injecting a unique collaborator URL and watching for an
// out-of-band callback. It only runs when an OOBClient is configured on the
// Service.
type oobInjectionCheck struct{}

func (oobInjectionCheck) ID() string   { return "oob-interaction" }
func (oobInjectionCheck) Name() string { return "Out-of-band interaction (blind SSRF/injection)" }

func (c oobInjectionCheck) Run(sc *ScanContext) []Finding {
	if sc.OOB == nil {
		return nil
	}

	token, cbURL := sc.OOB.NewToken()

	hostOnly := cbURL
	if i := strings.Index(cbURL, "://"); i >= 0 {
		hostOnly = cbURL[i+3:]
	}

	payloads := []string{
		cbURL,
		"//" + hostOnly,
		hostOnly,
	}

	var (
		lastReq *RequestTemplate
		lastRes *Response
	)

	for _, p := range payloads {
		res, req, err := sc.Send(p)
		if err == nil {
			lastReq = req
			lastRes = res
		}
	}

	deadline := time.Now().Add(OOBWaitTimeout)
	for time.Now().Before(deadline) {
		if sc.OOB.InteractionCount(token) > 0 {
			return []Finding{{
				Name:        c.Name(),
				Severity:    SeverityHigh,
				Confidence:  ConfidenceFirm,
				Payload:     cbURL,
				Evidence:    fmt.Sprintf("Target made an out-of-band callback to collaborator token %s.", token),
				Description: "The application fetched an attacker-supplied URL, producing an out-of-band interaction. This indicates blind SSRF or a blind injection that reaches a URL fetch.",
				Remediation: "Validate and allow-list outbound URLs, block requests to internal/link-local addresses, and avoid fetching user-supplied URLs where possible.",
				DedupKey:    "oob",
				Request:     lastReq,
				Response:    lastRes,
			}}
		}
		time.Sleep(oobPollInterval)
	}

	return nil
}
