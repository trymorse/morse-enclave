package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	"morse/backend/internal/health"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/web"
)

var (
	errNoSuchRoute        = apierr.Invalid(http.StatusNotFound, "not_found", "The worker serves no such route.")
	errDuplicateKey       = apierr.Invalid(http.StatusBadRequest, "duplicate_json_key", "A JSON object in the request body repeats a key, or spells one key in two cases. Send each key once.")
	errTooManyMessages    = apierr.Invalid(http.StatusBadRequest, "too_many_messages", "messages may hold at most "+strconv.Itoa(chat.MaxMessages)+" entries.")
	errTooManyValues      = apierr.Invalid(http.StatusBadRequest, "request_too_complex", "The request body may hold at most "+strconv.Itoa(chat.MaxJSONValues)+" JSON values.")
	errInvalidURL         = apierr.Invalid(http.StatusBadRequest, "invalid_url", "url must be an http or https URL of at most "+strconv.Itoa(web.MaxURLLength)+" characters, without credentials, on a public host and the default port, 80, or 443.")
	errInvalidOutputLimit = apierr.Invalid(http.StatusBadRequest, "invalid_output_limit", "max_tokens and max_completion_tokens must be positive integers when set.")
)

var ErrVideoExpired = apierr.Invalid(http.StatusGone, "video_expired", "The video was deleted: videos are kept for an hour after they finish, and only until one complete download.")

func refuse(ctx context.Context, w http.ResponseWriter, err error) {
	end, cut := cutOf(ctx, nil)
	cutByShutdown := cut && end == cutByProxy
	clientHungUpOrTimedOut := cut && !cutByShutdown
	var refusal apierr.Error
	switch {
	case cutByShutdown:
		apierr.WriteError(w, apierr.ErrShuttingDown)
	case errors.As(err, &refusal):
		apierr.WriteError(w, refusal)
	case errors.Is(err, e2ee.ErrNotApplied), errors.Is(err, chat.ErrUnsealedReply):
		apierr.WriteError(w, ErrE2EENotApplied)
	case clientHungUpOrTimedOut:
		return
	default:
		apierr.WriteError(w, apierr.ErrUpstream)
	}
}

func streamed(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(contentType), eventStreamType)
}

func evidenceOf(ctx context.Context, err, writeErr error, began bool) health.Evidence {
	evidence := health.Evidence{Err: faultOf(err), Began: began}
	if end, cut := cutOf(ctx, writeErr); cut {
		evidence.Cut = end.healthCut()
	}
	return evidence
}

func faultOf(err error) error {
	if errors.Is(err, chat.ErrSealBroken) || errors.Is(err, e2ee.ErrNotApplied) {
		return fmt.Errorf("%w: %w", apierr.ErrUnattested, err)
	}
	return err
}

var contentRefusals = apierr.Table{
	strictjson.ErrDuplicateKey: errDuplicateKey,
	chat.ErrTooManyMessages:    errTooManyMessages,
	chat.ErrTooManyValues:      errTooManyValues,
	chat.ErrInvalidOutputLimit: errInvalidOutputLimit,
	apierr.ErrRemoteMedia:      apierr.ErrRemoteMedia,
	web.ErrInvalidURL:          errInvalidURL,
}

func contentRefusal(err error) error {
	if refusal, ok := contentRefusals.Find(err); ok {
		return refusal
	}
	if invalid := strictjson.Invalid(""); errors.As(err, &invalid) {
		return apierr.InvalidParameter(string(invalid))
	}
	return err
}
