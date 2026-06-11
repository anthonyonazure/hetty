// Package screenshot captures PNG screenshots of URLs with headless Chrome
// (gowitness/eyewitness-style), used to build the attack-surface gallery of
// discovered live hosts.
package screenshot

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// Options configures a capture.
type Options struct {
	// WaitMs waits for the page to settle after navigation (default 1500).
	WaitMs int `json:"waitMs"`
	// Width/Height set the viewport (defaults 1280x800).
	Width  int `json:"width"`
	Height int `json:"height"`
	// FullPage captures the entire scrollable page when true.
	FullPage bool `json:"fullPage"`
	// TimeoutMs bounds the whole capture (default 30000).
	TimeoutMs int `json:"timeoutMs"`
}

// Result is a captured screenshot.
type Result struct {
	URL       string `json:"url"`
	PNGBase64 string `json:"pngBase64"`
	Bytes     int    `json:"bytes"`
}

func defaults(o *Options) {
	if o.WaitMs <= 0 {
		o.WaitMs = 1500
	}
	if o.Width <= 0 {
		o.Width = 1280
	}
	if o.Height <= 0 {
		o.Height = 800
	}
	if o.TimeoutMs <= 0 {
		o.TimeoutMs = 30000
	}
}

// Capture screenshots a single URL and returns the PNG as base64.
func Capture(ctx context.Context, rawURL string, opts Options) (Result, error) {
	defaults(&opts)

	ctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutMs)*time.Millisecond)
	defer cancel()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx,
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.NoFirstRun, chromedp.NoDefaultBrowserCheck, chromedp.IgnoreCertErrors,
			chromedp.WindowSize(opts.Width, opts.Height))...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	var buf []byte
	tasks := chromedp.Tasks{
		chromedp.Navigate(rawURL),
		chromedp.Sleep(time.Duration(opts.WaitMs) * time.Millisecond),
	}
	if opts.FullPage {
		tasks = append(tasks, chromedp.FullScreenshot(&buf, 90))
	} else {
		tasks = append(tasks, chromedp.CaptureScreenshot(&buf))
	}

	if err := chromedp.Run(browserCtx, tasks); err != nil {
		return Result{}, fmt.Errorf("screenshot: capture failed (is Chrome installed?): %w", err)
	}

	return Result{
		URL:       rawURL,
		PNGBase64: base64.StdEncoding.EncodeToString(buf),
		Bytes:     len(buf),
	}, nil
}
