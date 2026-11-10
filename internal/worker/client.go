package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/attested"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/health"
	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/seal"
	"morse/backend/internal/upstream"
)

type Client struct {
	base     string
	http     *http.Client
	mu       sync.Mutex
	draining bool
	counting map[Handle]struct{}
	counts   sync.WaitGroup
}

const (
	cutTimeout  = 10 * time.Second
	pollTimeout = 30 * time.Second
	// lateTimeout bounds the wait for a try a run left running, which ends by its stall deadline.
	lateTimeout = 30 * time.Minute
)

// An enclave that dies leaves no one to close its end of the tun, so only keepalive probes
// notice; Go's defaults take about 165 s, and the client's reply hangs for all of it.
func HTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 2 * time.Second, Interval: time.Second, Count: 3}}
	return &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext, MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second}}
}

func NewClient(base string, client *http.Client) *Client {
	return &Client{base: strings.TrimSuffix(base, "/"), http: client, counting: map[Handle]struct{}{}}
}

func (c *Client) Routes(ctx context.Context) (Served, error) {
	data, _, err := c.get(ctx, "/routes")
	if err != nil {
		return Served{}, err
	}
	var reply Served
	err = json.Unmarshal(data, &reply)
	return reply, err
}

func (c *Client) call(req *http.Request) ([]byte, http.Header, error) {
	resp, err := upstream.Do(c.http, req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", apierr.ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, wireRefusal(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxWireBody))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", apierr.ErrUnavailable, err)
	}
	return data, resp.Header, nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, nil, err
	}
	return c.call(req)
}

// A bodyErr keeps the error the relay's own body reader gave, which the transport may wrap or swallow when it
// aborts the send.
type bodyErr struct {
	io.Reader
	err error
}

func (b *bodyErr) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
	}
	return n, err
}

func (c *Client) Open(ctx context.Context, o Opening) (Admission, error) {
	var body io.Reader = http.NoBody
	sent := &bodyErr{}
	if o.Body != nil {
		sent.Reader = o.Body
		body = sent
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/open", body)
	if err != nil {
		return nil, err
	}
	for name, values := range o.Header {
		req.Header[name] = values
	}
	req.Header.Set(headerMethod, o.Method)
	req.Header.Set(headerPath, o.Path)
	req.Header.Set(headerQuery, o.Query)
	setOpening(req.Header, o.Cast, o.Framing, o.KeyCaller, o.KeyFloor, o.PrivacyVeil)
	data, _, err := c.call(req)
	if sent.err != nil {
		return nil, sent.err
	}
	if err != nil {
		return nil, err
	}
	opened, err := admissionOf(data)
	return opened.Admission, err
}

func (c *Client) OpenSealed(ctx context.Context, o SealedOpening) (SealedAdmission, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/open-sealed", bytes.NewReader(o.Body))
	if err != nil {
		return SealedAdmission{}, err
	}
	req.Header.Set("Content-Type", seal.ContentType)
	setOpening(req.Header, o.Cast, o.Framing, o.KeyCaller, o.KeyFloor, o.PrivacyVeil)
	data, header, err := c.call(req)
	switch {
	case err != nil:
		return SealedAdmission{}, err
	case header.Get("Content-Type") == seal.ContentType:
		return SealedAdmission{}, SealedRefusal{Reply: data}
	}
	return admissionOf(data)
}

func (c *Client) Unpinned(ctx context.Context) ([]attested.UnpinnedRelease, error) {
	data, _, err := c.get(ctx, "/unpinned")
	if err != nil {
		return nil, err
	}
	var reply unpinnedWire
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, fmt.Errorf("worker: /unpinned: %w", err)
	}
	return reply.Releases, nil
}

func (c *Client) Attestation(ctx context.Context) (Attested, error) {
	data, header, err := c.get(ctx, "/attestation")
	if err != nil {
		return Attested{}, err
	}
	var keyID seal.KeyID
	if err := keyID.UnmarshalText([]byte(header.Get(headerKeyID))); err != nil {
		return Attested{}, fmt.Errorf("worker: /attestation named no key: %w", err)
	}
	return Attested{Document: data, KeyID: keyID}, nil
}

func (c *Client) Run(ctx context.Context, h Handle, g Grant, reply http.ResponseWriter) Measured {
	e, err := grantWire(h, g)
	if err != nil {
		return unrunnable(reply)
	}
	return c.relay(ctx, "/run", e, h, reply)
}

func (c *Client) Submit(ctx context.Context, h Handle, g JobGrant, reply http.ResponseWriter, accepted func(media.Submitted)) Measured {
	var once sync.Once
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints {
			once.Do(func() {
				accepted(media.Submitted{VendorID: header.Get(headerVendorID)})
				c.ack(ctx, h)
			})
		}
		return nil
	}})
	return c.relay(ctx, "/submit", submitRequest{Handle: h, Grant: g}, h, reply)
}

func (c *Client) relay(ctx context.Context, path string, body any, h Handle, reply http.ResponseWriter) Measured {
	resp, err := c.send(ctx, path, body)
	switch {
	case errors.Is(err, upstream.ErrNotSent):
		return unreached(reply)
	case err != nil:
		panic(http.ErrAbortHandler)
	}
	defer resp.Body.Close()
	if _, announced := resp.Trailer[headerMeasured]; !announced {
		return unrunnable(reply)
	}
	header := reply.Header()
	for name, values := range resp.Header {
		if name == "Trailer" || strings.HasPrefix(name, "Worker-") {
			continue
		}
		header[name] = values
	}
	if length := resp.Header.Get(headerContentLength); length != "" {
		header.Set("Content-Length", length)
	}
	reply.WriteHeader(resp.StatusCode)
	copyFlushing(reply, resp.Body)
	m, err := measuredUnsamplingUnknownHealth(resp.Trailer.Get(headerMeasured))
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	if m.Follow != FollowNone {
		m.Counted = c.count(h)
	}
	if m.Lingers {
		m.Late = c.late(h)
	}
	return m
}

// late asks the worker for the tries a run left running, once they have all ended.
func (c *Client) late(h Handle) <-chan Try {
	out := make(chan Try)
	go func() {
		defer close(out)
		ctx, cancel := context.WithTimeout(context.Background(), lateTimeout)
		defer cancel()
		resp, err := c.post(ctx, "/late", handleRequest{Handle: h})
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var tries []wireTry
		if json.NewDecoder(io.LimitReader(resp.Body, maxWireBody)).Decode(&tries) != nil {
			return
		}
		for _, try := range knownTries(tries) {
			out <- try
		}
	}()
	return out
}

func measuredUnsamplingUnknownHealth(trailer string) (Measured, error) {
	var t struct {
		Measured
		Health     wireObservation
		FailedOver []wireTry
	}
	if err := json.Unmarshal([]byte(trailer), &t); err != nil {
		return Measured{}, err
	}
	m := t.Measured
	var known bool
	if m.Health, known = t.Health.known(); !known {
		m.Health, m.Unsampled = health.Observation{}, true
	}
	if m.PrivacyVeil != nil && m.PrivacyVeil.Failed != VeilOK {
		m.Unsampled = true
	}
	m.FailedOver = knownTries(t.FailedOver)
	return m, nil
}

type wireTry struct {
	Endpoint catalog.EndpointID
	Health   wireObservation
}

func knownTries(wire []wireTry) []Try {
	var tries []Try
	for _, try := range wire {
		if o, known := try.Health.known(); known {
			tries = append(tries, Try{Endpoint: try.Endpoint, Health: o})
		}
	}
	return tries
}

type wireObservation struct {
	health.Observation
	Outcome string
}

func (w wireObservation) known() (health.Observation, bool) {
	o := w.Observation
	return o, o.Outcome.UnmarshalText([]byte(w.Outcome)) == nil
}

func copyFlushing(w http.ResponseWriter, from io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				io.Copy(io.Discard, from)
				return
			}
			rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

func (c *Client) ack(ctx context.Context, h Handle) {
	resp, err := c.post(ctx, "/ack", handleRequest{Handle: h})
	if err == nil {
		resp.Body.Close()
	}
}

// The drain marks itself under the lock and a new count checks for it under the lock, because a WaitGroup
// forbids an Add once Wait may be running on a zero count.
func (c *Client) count(h Handle) <-chan Count {
	out := make(chan Count, 1)
	c.mu.Lock()
	if c.draining {
		c.mu.Unlock()
		c.Cut(h, measure.CutByProxy)
		close(out)
		return out
	}
	c.counting[h] = struct{}{}
	c.counts.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.counts.Done()
		defer close(out)
		defer func() {
			c.mu.Lock()
			delete(c.counting, h)
			c.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), OpenedFor)
		defer cancel()
		resp, err := c.post(ctx, "/count", handleRequest{Handle: h})
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var counted Count
		if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, maxWireBody)).Decode(&counted) != nil {
			return
		}
		out <- counted
	}()
	return out
}

func (c *Client) Cut(h Handle, reason measure.Cut) {
	ctx, cancel := context.WithTimeout(context.Background(), cutTimeout)
	defer cancel()
	if resp, err := c.post(ctx, "/cut", cutRequest{Handle: h, Reason: reason}); err == nil {
		resp.Body.Close()
	}
}

func (c *Client) Poll(ctx context.Context, route, vendorID string) (jobs.Poll, error) {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	resp, err := c.send(ctx, "/poll", pollRequest{Route: route, VendorID: vendorID, Deadline: deadline})
	if err != nil {
		return jobs.Poll{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		refusal := wireRefusal(resp)
		if status, err := strconv.Atoi(resp.Header.Get(headerVendorStatus)); err == nil {
			return jobs.Poll{}, upstream.Refused{Status: status, Err: refusal}
		}
		return jobs.Poll{}, refusal
	}
	var p jobs.Poll
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWireBody)).Decode(&p); err != nil {
		return jobs.Poll{}, err
	}
	return p, nil
}

func (c *Client) Attest(ctx context.Context, v Vendor, nonce string, f Format) (chat.Attestation, error) {
	var att attestationWire
	if err := c.evidence(ctx, "/attest", attestRequest(v, nonce, f), &att); err != nil {
		return chat.Attestation{}, err
	}
	return chat.Attestation{Report: att.Report, BindModel: att.BindModel, GPUVerdicts: att.GPUVerdicts, VendorPins: att.VendorPins}, nil
}

func (c *Client) Receipt(ctx context.Context, v Vendor, id string) (json.RawMessage, error) {
	var receipt json.RawMessage
	err := c.evidence(ctx, "/receipt", evidenceRequest{Vendor: v, ID: id}, &receipt)
	return receipt, err
}

func (c *Client) Session(ctx context.Context, v Vendor, id string) (json.RawMessage, error) {
	var record json.RawMessage
	err := c.evidence(ctx, "/session", evidenceRequest{Vendor: v, ID: id}, &record)
	return record, err
}

func (c *Client) Sessions(ctx context.Context, v Vendor) ([]chat.ListedSession, error) {
	var listed sessionsWire
	err := c.evidence(ctx, "/sessions", evidenceRequest{Vendor: v}, &listed)
	return listed.Sessions, err
}

func (c *Client) evidence(ctx context.Context, path string, req evidenceRequest, into any) error {
	resp, err := c.post(ctx, path, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSealedWire))
	if err != nil {
		return err
	}
	if raw, ok := into.(*json.RawMessage); ok {
		*raw = body
		return nil
	}
	return json.Unmarshal(body, into)
}

// A drain cuts every count the relay is still collecting, so the worker ends each at once, and then collects
// what each had, so a count that finished before the drain still settles its charge.
func (c *Client) Drain() {
	c.mu.Lock()
	c.draining = true
	counting := make([]Handle, 0, len(c.counting))
	for h := range c.counting {
		counting = append(counting, h)
	}
	c.mu.Unlock()
	for _, h := range counting {
		c.Cut(h, measure.CutByProxy)
	}
	c.counts.Wait()
}

func (c *Client) post(ctx context.Context, path string, body any) (*http.Response, error) {
	resp, err := c.send(ctx, path, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, wireRefusal(resp)
	}
	return resp, nil
}

func (c *Client) send(ctx context.Context, path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return upstream.Do(c.http, req)
}

var _ Worker = (*Client)(nil)
