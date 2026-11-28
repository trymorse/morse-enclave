package spicyapi

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/health"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

const (
	createPath = "/api/v1/jobs/createTask"
	recordPath = "/api/v1/jobs/recordInfo"
	purgePath  = "/api/v1/jobs/purge"
	ticketPath = "/api/v1/common/upload-url"
	commitPath = "/api/v1/files/"

	// why: createTask's ?wait holds the connection until the task ends, capped at 60 s under spicyapi.ai's 100 s CDN cut
	// (https://docs.spicyapi.ai/docs/tasks#wait).
	waitSeconds = 30

	// why: X-Spicy-Retention also times the prompt from acceptance, so a window shorter than our own wait could clear a
	// queued task's prompt; purge clears both once the task ends (https://docs.spicyapi.ai/docs/retention).
	retention = media.ImageTimeout + 5*time.Minute

	succeeded       = "succeeded"
	contentRejected = "content_rejected"

	attempts     = 3
	retryAfter   = time.Second
	purgeWithin  = 3 * time.Second
	settleTries  = 4
	settleFirst  = 500 * time.Millisecond
	settleWithin = 10 * time.Second
)

var (
	taskID  = regexp.MustCompile(`^job_[0-9A-Za-z]{1,64}$`)
	fileID  = regexp.MustCompile(`^fil_[0-9A-Za-z]{1,64}$`)
	fileURI = regexp.MustCompile(`^spicy://f/fil_[0-9A-Za-z]{1,64}$`)

	errOffBucket = fmt.Errorf("%w: a link outside spicyapi.ai's bucket", upstream.ErrMalformed)
	errUntrusted = health.ResultRefused{Why: health.RefusedUntrustedLink, Err: errOffBucket}
)

type bucket struct {
	host func(host string) bool
	path string
}

// why: spicyapi.ai signs links on <account-id>.r2.cloudflarestorage.com, and any R2 account can name a bucket alike, so
// only its own account, seen on every link of the first dev calls on 2026-11-17, is followed (docs.spicyapi.ai/docs/media).
var spicyR2Accounts = []string{"fee727dd104ab86a982d8b79462c32a3"}

// why: since 2026-11-27 spicyapi.ai links finished results on its own host (seen on a dev task), while uploads and
// its documented result links stay on R2, so a result is followed on either.
const spicyFilesHost = "files.spicyapi.ai"

func PinsStorage() bool { return len(spicyR2Accounts) > 0 }

func r2Accounts(ids []string) func(host string) bool {
	return func(host string) bool {
		id, ok := strings.CutSuffix(host, ".r2.cloudflarestorage.com")
		return ok && slices.Contains(ids, id)
	}
}

var (
	resultsBucket = bucket{host: r2Accounts(spicyR2Accounts), path: "/spicy-production-results/"}
	inputsBucket  = bucket{host: r2Accounts(spicyR2Accounts), path: "/spicy-production-inputs/"}
	resultsHost   = bucket{host: func(host string) bool { return host == spicyFilesHost }, path: "/r/tasks/"}
)

func (b bucket) holds(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || !b.host(u.Host) {
		return false
	}
	return strings.HasPrefix(u.Path, b.path) && !strings.Contains(u.Path, "/../") && !strings.Contains(u.Path, "//")
}

type client struct {
	api     upstream.Endpoint
	storage *http.Client
	results bucket
	files   bucket
	inputs  bucket
	Poll    time.Duration
}

func newClient(baseURL, apiKey string, httpClient *http.Client) client {
	api := upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: httpClient, Refuse: refusal}
	return client{api: api, storage: httpClient, results: resultsBucket, files: resultsHost, inputs: inputsBucket}
}

func (c client) holdsResult(link string) bool { return c.results.holds(link) || c.files.holds(link) }

type envelope struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
}

func (c client) call(ctx context.Context, r upstream.Request, into any) error {
	var env envelope
	if _, err := c.api.JSON(ctx, r, &env, media.MaxReplyBody); err != nil {
		return err
	}
	if env.Code != http.StatusOK || json.Unmarshal(env.Data, into) != nil {
		return upstream.ErrMalformed
	}
	return nil
}

// why: a refusal's msg can quote the request, so only its HTTP status is read: 402 is a dry balance or spend cap
// (40201, 40202) and 403 a key, account or region refusal (40301-40310) (https://docs.spicyapi.ai/docs/errors).
func refusal(r upstream.Reply) error { return apierr.SanitizedUpstreamError(r.Status, nil) }

type asset struct {
	URL         string `json:"url"`
	Pending     bool   `json:"pending"`
	Unavailable bool   `json:"unavailable"`
}

type record struct {
	TaskID    string `json:"taskId"`
	State     string `json:"state"`
	ErrorCode string `json:"errorCode"`
	Output    struct {
		Assets []asset `json:"assets"`
	} `json:"output"`
	Cost         string `json:"cost"`
	Settled      bool   `json:"settled"`
	ContentState string `json:"contentState"`
	CompletedAt  string `json:"completedAt"`
	Retention    struct {
		OutputsExpireAt string `json:"outputsExpireAt"`
	} `json:"retention"`
}

// why: once retention has run, or its window has passed, spicyapi.ai holds no content for purge to destroy
// (https://docs.spicyapi.ai/docs/retention).
func (r record) cleared(now time.Time) bool {
	if r.ContentState == expired || r.ContentState == "purged" {
		return true
	}
	if at, err := time.Parse(time.RFC3339, r.Retention.OutputsExpireAt); err == nil {
		return now.After(at)
	}
	if at, err := time.Parse(time.RFC3339, r.CompletedAt); err == nil {
		return now.After(at.Add(media.VendorKeep))
	}
	return false
}

// why: spicyapi.ai asks that every state but queued and running count as final, and a pending asset is still being
// copied to storage, with no link yet (https://docs.spicyapi.ai/docs/tasks#output).
func (r record) done() bool {
	if r.State == "queued" || r.State == "running" {
		return false
	}
	for _, a := range r.Output.Assets {
		if a.Pending {
			return false
		}
	}
	return true
}

// why: until settled is true, cost is spicyapi.ai's hold and can still change (https://docs.spicyapi.ai/docs/tasks).
func (r record) cost() money.Reported {
	if !r.Settled {
		return money.Reported{}
	}
	return money.ReportedUSD(r.Cost)
}

func failure(errorCode string) error {
	switch errorCode {
	case contentRejected:
		return apierr.ErrContentFilter
	case "invalid_request", "unsupported_combination", "invalid_asset":
		return apierr.ErrInvalidRequest
	case "rate_limited":
		return apierr.ErrUpstreamBusy
	case "upstream_unavailable":
		return apierr.ErrUpstreamUnavailable
	}
	return apierr.ErrUpstream
}

type task struct {
	Model string `json:"model"`
	Input any    `json:"input"`
}

// why: an accepted task is billed and cannot be cancelled, so every attempt carries one Idempotency-Key and a retry
// gets back the task the first made (https://docs.spicyapi.ai/docs/idempotency).
func (c client) create(ctx context.Context, t task, idempotencyKey string, wait int, keep time.Duration) (record, error) {
	h := http.Header{}
	h.Set("Idempotency-Key", idempotencyKey)
	h.Set("X-Spicy-Retention", strconv.Itoa(int(keep/time.Second)))
	path := createPath
	if wait > 0 {
		path += "?wait=" + strconv.Itoa(wait)
	}
	req := upstream.Request{Method: http.MethodPost, Path: path, Header: h, Body: jsonx.Encode(t)}
	var rec record
	var err error
	for range attempts {
		if err = c.call(ctx, req, &rec); err == nil || upstream.Final(err, upstream.UnusableRetries) || !c.pause(ctx) {
			break
		}
	}
	if err == nil && !taskID.MatchString(rec.TaskID) {
		return record{}, upstream.ErrMalformed
	}
	return rec, err
}

func (c client) record(ctx context.Context, id string) (record, error) {
	var rec record
	if err := c.call(ctx, upstream.Request{Method: http.MethodGet, Path: recordPath + "?taskId=" + url.QueryEscape(id)}, &rec); err != nil {
		return record{}, err
	}
	if rec.TaskID != id {
		return record{}, upstream.ErrMalformed
	}
	return rec, nil
}

func (c client) await(ctx context.Context, rec record) (record, error) {
	if rec.done() {
		return rec, nil
	}
	err := media.PollUntil(ctx, c.Poll, func(ctx context.Context) (bool, error) {
		next, err := c.record(ctx, rec.TaskID)
		if err != nil {
			if upstream.Final(err, upstream.UnusableEnds) {
				return true, err
			}
			return false, nil
		}
		rec = next
		return rec.done(), nil
	})
	return rec, err
}

// why: until settled is true a task's cost is spicyapi.ai's hold, and it settles after the task ends
// (https://docs.spicyapi.ai/docs/tasks).
func (c client) settle(ctx context.Context, rec record) record {
	ctx, stop := context.WithTimeout(ctx, settleWithin)
	defer stop()
	wait := cmp.Or(c.Poll, settleFirst)
	for range settleTries {
		if rec.Settled || !sleep(ctx, wait) {
			break
		}
		if next, err := c.record(ctx, rec.TaskID); err == nil && next.Settled {
			rec = next
		}
		wait *= 2
	}
	return rec
}

// why: purge destroys a final task's prompt, result and files at once, is idempotent, and never refunds or cancels
// (https://docs.spicyapi.ai/docs/retention#destroying-content-on-demand-post-jobspurge).
func (c client) purge(ctx context.Context, id string) error {
	ctx, stop := context.WithTimeout(context.WithoutCancel(ctx), purgeWithin)
	defer stop()
	reply, err := c.api.Call(ctx, upstream.Request{Method: http.MethodPost, Path: purgePath, Body: jsonx.Encode(map[string]string{"taskId": id})}, media.MaxReplyBody)
	switch {
	case err != nil:
		return err
	case reply.Status == http.StatusForbidden:
		return media.ErrPurgeRefused
	case upstream.Refused{Status: reply.Status}.Transient():
		return refusal(reply)
	}
	return nil
}

func (c client) storageAt(link string) upstream.Endpoint {
	return upstream.Endpoint{BaseURL: link, HTTP: c.storage, Refuse: func(upstream.Reply) error { return apierr.ErrUpstream }}
}

// why: a result link is signed and carries its own credential, so it is fetched with no key
// (https://docs.spicyapi.ai/docs/media#download).
func (c client) fetch(ctx context.Context, link string) (media.Image, error) {
	if !c.holdsResult(link) {
		return media.Image{}, errUntrusted
	}
	reply, err := c.storageAt(link).JSON(ctx, upstream.Request{Method: http.MethodGet, Header: http.Header{"Accept": {"*/*"}}}, nil, media.MaxImagesBody)
	if err != nil {
		return media.Image{}, err
	}
	return media.ImageOf(reply.Body)
}

type ticket struct {
	FileID    string `json:"fileId"`
	UploadURL string `json:"uploadUrl"`
	Method    string `json:"method"`
}

type committed struct {
	URI string `json:"uri"`
}

// why: an inline data URI takes at most 1 MiB an image and 2 MiB a body and is kept as an upload all the same, so
// every reference is uploaded: a ticket, a PUT to its signed link, a commit (https://docs.spicyapi.ai/docs/media).
func (c client) upload(ctx context.Context, mediaType string, data []byte) (string, error) {
	var t ticket
	body := jsonx.Encode(map[string]any{"contentType": mediaType, "bytes": len(data)})
	if err := c.call(ctx, upstream.Request{Method: http.MethodPost, Path: ticketPath, Body: body}, &t); err != nil {
		return "", err
	}
	if !fileID.MatchString(t.FileID) || t.Method != http.MethodPut {
		return "", errOffBucket
	}
	if !c.inputs.holds(t.UploadURL) {
		return "", errUntrusted
	}
	put := upstream.Request{Method: http.MethodPut, Header: http.Header{"Content-Type": {mediaType}}, Body: data}
	if _, err := c.storageAt(t.UploadURL).JSON(ctx, put, nil, media.MaxReplyBody); err != nil {
		return "", err
	}
	var done committed
	var err error
	for range attempts {
		err = c.call(ctx, upstream.Request{Method: http.MethodPost, Path: commitPath + t.FileID + "/commit"}, &done)
		if !stillVerifying(err) || !c.pause(ctx) {
			break
		}
	}
	if err != nil {
		return "", err
	}
	if !fileURI.MatchString(done.URI) {
		return "", upstream.ErrMalformed
	}
	return done.URI, nil
}

// why: commit answers 409 or 429 while spicyapi.ai still verifies the file, and a repeated commit is idempotent
// (https://docs.spicyapi.ai/docs/media#commit).
func stillVerifying(err error) bool {
	var r upstream.Refused
	if errors.As(err, &r) {
		return r.Status == http.StatusConflict || r.Status == http.StatusTooManyRequests
	}
	return err != nil && !errors.Is(err, upstream.ErrMalformed)
}

func (c client) pause(ctx context.Context) bool { return sleep(ctx, cmp.Or(c.Poll, retryAfter)) }

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
