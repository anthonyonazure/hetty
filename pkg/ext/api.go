package ext

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/dop251/goja"
	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/scan"
)

var zeroULID ulid.ULID

// maxSendBody caps the body read by hetty.send().
const maxSendBody = 5 << 20 // 5 MiB

// Extension is a single loaded JavaScript extension and its runtime.
type Extension struct {
	name        string
	path        string
	version     string
	description string

	vm     *goja.Runtime
	engine *Engine

	// mu guards all access to vm after load, since a goja.Runtime is not safe
	// for concurrent use.
	mu sync.Mutex

	reqHooks      []goja.Callable
	resHooks      []goja.Callable
	activeChecks  []scan.ActiveCheck
	passiveChecks []scan.PassiveCheck

	// curReq is the request being processed during a hook, attached to issues
	// raised via hetty.raiseIssue().
	curReq *scan.RequestTemplate
}

func (ext *Extension) info() Info {
	return Info{
		Name:          ext.name,
		Version:       ext.version,
		Description:   ext.description,
		Path:          ext.path,
		RequestHooks:  len(ext.reqHooks),
		ResponseHooks: len(ext.resHooks),
		ActiveChecks:  len(ext.activeChecks),
		PassiveChecks: len(ext.passiveChecks),
	}
}

// installHostAPI binds the `hetty` global (and a minimal `console`) into the
// extension's runtime. This runs during load, before user code executes.
func installHostAPI(e *Engine, ext *Extension) {
	vm := ext.vm
	hetty := vm.NewObject()

	logFn := func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, a := range call.Arguments {
			parts = append(parts, a.String())
		}
		e.logger.Infow(fmt.Sprintf("[ext:%s] %s", ext.name, strings.Join(parts, " ")))

		return goja.Undefined()
	}
	_ = hetty.Set("log", logFn)

	_ = hetty.Set("meta", func(call goja.FunctionCall) goja.Value {
		if o, ok := call.Argument(0).Export().(map[string]interface{}); ok {
			if v, ok := o["name"].(string); ok && v != "" {
				ext.name = v
			}
			if v, ok := o["version"].(string); ok && v != "" {
				ext.version = v
			}
			if v, ok := o["description"].(string); ok {
				ext.description = v
			}
		}

		return goja.Undefined()
	})

	_ = hetty.Set("on", func(call goja.FunctionCall) goja.Value {
		event := call.Argument(0).String()
		fn, ok := goja.AssertFunction(call.Argument(1))
		if !ok {
			panic(vm.NewTypeError("hetty.on: second argument must be a function"))
		}

		switch event {
		case "request":
			ext.reqHooks = append(ext.reqHooks, fn)
		case "response":
			ext.resHooks = append(ext.resHooks, fn)
		default:
			panic(vm.NewTypeError(fmt.Sprintf("hetty.on: unknown event %q (want \"request\" or \"response\")", event)))
		}

		return goja.Undefined()
	})

	_ = hetty.Set("send", func(call goja.FunctionCall) goja.Value {
		return ext.hostSend(call)
	})

	_ = hetty.Set("raiseIssue", func(call goja.FunctionCall) goja.Value {
		if f := issueFromJS(vm, call.Argument(0)); f != nil {
			e.recordIssue("ext:"+ext.name, ext.curReq, *f)
		}

		return goja.Undefined()
	})

	_ = hetty.Set("registerActiveCheck", func(call goja.FunctionCall) goja.Value {
		ext.registerActiveCheck(call)
		return goja.Undefined()
	})

	_ = hetty.Set("registerPassiveCheck", func(call goja.FunctionCall) goja.Value {
		ext.registerPassiveCheck(call)
		return goja.Undefined()
	})

	_ = vm.Set("hetty", hetty)

	// Provide console.log/console.error as conveniences.
	console := vm.NewObject()
	_ = console.Set("log", logFn)
	_ = console.Set("error", logFn)
	_ = console.Set("warn", logFn)
	_ = vm.Set("console", console)
}

// hostSend implements hetty.send({method,url,headers,body}).
func (ext *Extension) hostSend(call goja.FunctionCall) goja.Value {
	vm := ext.vm

	arg, ok := call.Argument(0).Export().(map[string]interface{})
	if !ok {
		panic(vm.NewTypeError("hetty.send: argument must be an object"))
	}

	method := strings.ToUpper(mapStr(arg, "method", http.MethodGet))
	rawURL := mapStr(arg, "url", "")
	if rawURL == "" {
		panic(vm.NewTypeError("hetty.send: 'url' is required"))
	}

	body := mapStr(arg, "body", "")

	httpReq, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		panic(vm.ToValue("hetty.send: " + err.Error()))
	}

	if hs, ok := arg["headers"].(map[string]interface{}); ok {
		for k, v := range hs {
			httpReq.Header.Set(k, fmt.Sprint(v))
		}
	}

	res, err := ext.engine.httpClient.Do(httpReq)
	if err != nil {
		panic(vm.ToValue("hetty.send: " + err.Error()))
	}
	defer res.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(res.Body, maxSendBody))

	out := map[string]interface{}{
		"status":     res.StatusCode,
		"statusText": res.Status,
		"headers":    headersToMap(res.Header),
		"body":       string(respBody),
	}

	return vm.ToValue(out)
}

// --- Hook execution --------------------------------------------------------

func (ext *Extension) runRequestHooks(rt *scan.RequestTemplate) (changed bool) {
	ext.mu.Lock()
	defer ext.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			ext.engine.logger.Errorw("Extension request hook panicked.", "ext", ext.name, "recover", r)
		}
	}()

	ext.curReq = rt
	defer func() { ext.curReq = nil }()

	obj := ext.requestObject(rt)

	for _, fn := range ext.reqHooks {
		if _, err := fn(goja.Undefined(), obj); err != nil {
			ext.engine.logger.Errorw("Extension request hook error.", "ext", ext.name, "error", err)
		}
	}

	ext.readRequestObject(obj, rt)

	return true
}

func (ext *Extension) runResponseHooks(reqTmpl *scan.RequestTemplate, sr *scan.Response) (changed bool) {
	ext.mu.Lock()
	defer ext.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			ext.engine.logger.Errorw("Extension response hook panicked.", "ext", ext.name, "recover", r)
		}
	}()

	ext.curReq = reqTmpl
	defer func() { ext.curReq = nil }()

	resObj := ext.responseObject(sr)

	var reqObj goja.Value = goja.Undefined()
	if reqTmpl != nil {
		reqObj = ext.requestObject(reqTmpl)
	}

	for _, fn := range ext.resHooks {
		if _, err := fn(goja.Undefined(), resObj, reqObj); err != nil {
			ext.engine.logger.Errorw("Extension response hook error.", "ext", ext.name, "error", err)
		}
	}

	ext.readResponseObject(resObj, sr)

	return true
}

// --- JS object marshaling --------------------------------------------------

func (ext *Extension) requestObject(rt *scan.RequestTemplate) *goja.Object {
	o := ext.vm.NewObject()
	_ = o.Set("method", rt.Method)

	if rt.URL != nil {
		_ = o.Set("url", rt.URL.String())
		_ = o.Set("scheme", rt.URL.Scheme)
		_ = o.Set("host", rt.URL.Host)
		_ = o.Set("path", rt.URL.Path)
		_ = o.Set("query", rt.URL.RawQuery)
	}

	_ = o.Set("headers", ext.headerObject(rt.Header))
	_ = o.Set("body", string(rt.Body))

	return o
}

func (ext *Extension) readRequestObject(o *goja.Object, rt *scan.RequestTemplate) {
	if m := getString(o, "method"); m != "" {
		rt.Method = m
	}

	if h := getObject(ext.vm, o, "headers"); h != nil {
		rt.Header = readHeaderObject(h)
	}

	if b := o.Get("body"); b != nil && !goja.IsUndefined(b) && !goja.IsNull(b) {
		rt.Body = []byte(b.String())
	}
}

func (ext *Extension) responseObject(sr *scan.Response) *goja.Object {
	o := ext.vm.NewObject()
	if sr == nil {
		return o
	}

	_ = o.Set("status", sr.StatusCode)
	_ = o.Set("headers", ext.headerObject(sr.Header))
	_ = o.Set("body", string(sr.Body))
	_ = o.Set("duration_ms", sr.Duration.Milliseconds())

	return o
}

func (ext *Extension) readResponseObject(o *goja.Object, sr *scan.Response) {
	if s := o.Get("status"); s != nil && !goja.IsUndefined(s) && !goja.IsNull(s) {
		if code := int(s.ToInteger()); code > 0 {
			sr.StatusCode = code
		}
	}

	if h := getObject(ext.vm, o, "headers"); h != nil {
		sr.Header = readHeaderObject(h)
	}

	if b := o.Get("body"); b != nil && !goja.IsUndefined(b) && !goja.IsNull(b) {
		sr.Body = []byte(b.String())
	}
}

func (ext *Extension) headerObject(h http.Header) *goja.Object {
	o := ext.vm.NewObject()
	for k, vals := range h {
		if len(vals) > 0 {
			_ = o.Set(k, vals[0])
		}
	}

	return o
}

// --- Custom scan checks ----------------------------------------------------

func (ext *Extension) registerActiveCheck(call goja.FunctionCall) {
	vm := ext.vm

	obj := call.Argument(0).ToObject(vm)
	if obj == nil {
		panic(vm.NewTypeError("registerActiveCheck: argument must be an object"))
	}

	detect, ok := goja.AssertFunction(obj.Get("detect"))
	if !ok {
		panic(vm.NewTypeError("registerActiveCheck: 'detect' must be a function"))
	}

	id := getStringDefault(obj, "id", "ext-active")

	check := &jsActiveCheck{
		ext:        ext,
		id:         "ext:" + ext.name + ":" + id,
		name:       getStringDefault(obj, "name", id),
		severity:   scan.Severity(getStringDefault(obj, "severity", string(scan.SeverityMedium))),
		confidence: scan.Confidence(getStringDefault(obj, "confidence", string(scan.ConfidenceFirm))),
		payloads:   exportStringSlice(obj.Get("payloads")),
		detect:     detect,
	}

	ext.activeChecks = append(ext.activeChecks, check)
}

func (ext *Extension) registerPassiveCheck(call goja.FunctionCall) {
	vm := ext.vm

	obj := call.Argument(0).ToObject(vm)
	if obj == nil {
		panic(vm.NewTypeError("registerPassiveCheck: argument must be an object"))
	}

	run, ok := goja.AssertFunction(obj.Get("run"))
	if !ok {
		panic(vm.NewTypeError("registerPassiveCheck: 'run' must be a function"))
	}

	id := getStringDefault(obj, "id", "ext-passive")

	check := &jsPassiveCheck{
		ext:  ext,
		id:   "ext:" + ext.name + ":" + id,
		name: getStringDefault(obj, "name", id),
		run:  run,
	}

	ext.passiveChecks = append(ext.passiveChecks, check)
}

type jsActiveCheck struct {
	ext        *Extension
	id         string
	name       string
	severity   scan.Severity
	confidence scan.Confidence
	payloads   []string
	detect     goja.Callable
}

func (c *jsActiveCheck) ID() string   { return c.id }
func (c *jsActiveCheck) Name() string { return c.name }

func (c *jsActiveCheck) Run(sc *scan.ScanContext) []scan.Finding {
	var findings []scan.Finding

	for _, payload := range c.payloads {
		res, req, err := sc.Send(payload)
		if err != nil || res == nil {
			continue
		}

		f := c.callDetect(c.detect, payload, res, sc.Baseline)
		if f == nil {
			continue
		}

		if f.Name == "" {
			f.Name = c.name
		}
		if f.Severity == "" {
			f.Severity = c.severity
		}
		if f.Confidence == "" {
			f.Confidence = c.confidence
		}
		f.Payload = payload
		f.Request = req
		f.Response = res

		findings = append(findings, *f)
	}

	return findings
}

func (c *jsActiveCheck) callDetect(detect goja.Callable, payload string, res, baseline *scan.Response) (f *scan.Finding) {
	ext := c.ext
	ext.mu.Lock()
	defer ext.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			ext.engine.logger.Errorw("Extension active check panicked.", "check", c.id, "recover", r)
			f = nil
		}
	}()

	ret, err := detect(
		goja.Undefined(),
		ext.vm.ToValue(payload),
		ext.responseObject(res),
		ext.responseObject(baseline),
	)
	if err != nil {
		ext.engine.logger.Errorw("Extension active check error.", "check", c.id, "error", err)
		return nil
	}

	return issueFromJS(ext.vm, ret)
}

type jsPassiveCheck struct {
	ext  *Extension
	id   string
	name string
	run  goja.Callable
}

func (c *jsPassiveCheck) ID() string   { return c.id }
func (c *jsPassiveCheck) Name() string { return c.name }

func (c *jsPassiveCheck) Check(req *scan.RequestTemplate, res *scan.Response) (findings []scan.Finding) {
	ext := c.ext
	ext.mu.Lock()
	defer ext.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			ext.engine.logger.Errorw("Extension passive check panicked.", "check", c.id, "recover", r)
			findings = nil
		}
	}()

	var reqVal goja.Value = goja.Undefined()
	if req != nil {
		reqVal = ext.requestObject(req)
	}

	ret, err := c.run(goja.Undefined(), reqVal, ext.responseObject(res))
	if err != nil {
		ext.engine.logger.Errorw("Extension passive check error.", "check", c.id, "error", err)
		return nil
	}

	for _, f := range findingsFromJS(ext.vm, ret) {
		if f.Name == "" {
			f.Name = c.name
		}
		findings = append(findings, f)
	}

	return findings
}

// --- JS <-> Go helpers -----------------------------------------------------

func headersToMap(h http.Header) map[string]interface{} {
	m := make(map[string]interface{}, len(h))
	for k, vals := range h {
		if len(vals) > 0 {
			m[k] = vals[0]
		}
	}

	return m
}

func readHeaderObject(ho *goja.Object) http.Header {
	h := make(http.Header)
	for _, k := range ho.Keys() {
		v := ho.Get(k)
		if v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
			h.Set(k, v.String())
		}
	}

	return h
}

func getString(o *goja.Object, key string) string {
	v := o.Get(key)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}

	return v.String()
}

func getStringDefault(o *goja.Object, key, def string) string {
	if s := getString(o, key); s != "" {
		return s
	}

	return def
}

func getObject(vm *goja.Runtime, o *goja.Object, key string) *goja.Object {
	v := o.Get(key)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}

	return v.ToObject(vm)
}

func mapStr(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}

	return def
}

func exportStringSlice(v goja.Value) []string {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}

	exported := v.Export()
	arr, ok := exported.([]interface{})
	if !ok {
		return nil
	}

	out := make([]string, 0, len(arr))
	for _, item := range arr {
		out = append(out, fmt.Sprint(item))
	}

	return out
}

// issueFromJS converts a JS return value into a single Finding. A bare `true`
// produces a minimal finding; an object maps field-by-field; anything falsey
// yields nil.
func issueFromJS(vm *goja.Runtime, v goja.Value) *scan.Finding {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}

	if b, ok := v.Export().(bool); ok {
		if !b {
			return nil
		}
		return &scan.Finding{Severity: scan.SeverityMedium, Confidence: scan.ConfidenceFirm}
	}

	o := v.ToObject(vm)
	if o == nil {
		return nil
	}

	return &scan.Finding{
		Name:        getString(o, "name"),
		Severity:    scan.Severity(getString(o, "severity")),
		Confidence:  scan.Confidence(getString(o, "confidence")),
		Description: getString(o, "description"),
		Remediation: getString(o, "remediation"),
		Evidence:    getString(o, "evidence"),
		DedupKey:    getString(o, "dedupKey"),
	}
}

// findingsFromJS handles a JS return that is either a single issue or an array
// of issues.
func findingsFromJS(vm *goja.Runtime, v goja.Value) []scan.Finding {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}

	if arr, ok := v.Export().([]interface{}); ok {
		out := make([]scan.Finding, 0, len(arr))
		for _, item := range arr {
			if f := issueFromJS(vm, vm.ToValue(item)); f != nil {
				out = append(out, *f)
			}
		}
		return out
	}

	if f := issueFromJS(vm, v); f != nil {
		return []scan.Finding{*f}
	}

	return nil
}
