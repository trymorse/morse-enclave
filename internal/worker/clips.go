package worker

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"morse/backend/internal/apierr"
	"morse/backend/internal/clip"
	"morse/backend/internal/uuid"
)

type SealedClips struct {
	Origin  clip.Origin
	Store   clip.Store
	Tickets clip.TicketKeys
}

var errNoClipTickets = errors.New("worker: sealed clips need the fleet key their upload tickets are sealed under")

var (
	errClipsSealedOnly  = apierr.Invalid(http.StatusForbidden, "sealed_required", "This model's video is sealed under a key only the device that asked for it holds, so the worker takes the request only sealed and hands the key back only in a sealed reply.")
	errClipStoreRefused = apierr.Error{Status: http.StatusBadGateway, Type: "server_error", Code: "clip_store_refused", Message: "The relay asked for the video to go somewhere other than the sealed clip store."}
	errClipTicketsHeld  = apierr.Error{Status: http.StatusServiceUnavailable, Type: "server_error", Code: "ticket_key_pending", Message: "This enclave is taking the key its fleet seals upload addresses under, which it does in the first minutes after it starts. Send the video again shortly."}
	errClipKeyRequired  = apierr.Invalid(http.StatusBadRequest, "clip_key_required", "This video is sealed under a key only the device that asked for it holds. Send that key, the clip_key its sealed POST /v1/videos reply carried, in the "+clip.KeyHeader+" header of a sealed request.")
	errClipKeyInvalid   = apierr.Invalid(http.StatusBadRequest, "clip_key_invalid", "The video does not open under the key in the "+clip.KeyHeader+" header, which must be the clip_key its sealed POST /v1/videos reply carried.")
	errClipUnopened     = apierr.Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "video_unreadable", Message: "The stored video does not open under its key."}
)

const clipPrefix = "video_"

func clipName(id string) (string, bool) {
	raw, prefixed := strings.CutPrefix(id, clipPrefix)
	u, ok := uuid.Parse(raw)
	return clipPrefix + uuid.Format(u), prefixed && ok
}

func (w *InProcess) sealsClipsOf(route string) bool { return w.clips != nil && w.uploadsVideo[route] }

func (s *SealedClips) uploadURL(g JobGrant) (string, clip.Key, error) {
	name, ok := clipName(g.ID)
	if !ok || !s.Store.Holds(g.UploadURL) {
		return "", clip.Key{}, errClipStoreRefused
	}
	tickets, held := s.Tickets()
	if !held {
		return "", clip.Key{}, errClipTicketsHeld
	}
	key := clip.NewKey()
	return clip.Ticket{Key: key, Clip: name, Store: g.UploadURL, Deadline: g.Deadline}.URL(s.Origin, tickets), key, nil
}

func (s *SealedClips) open(id, sentKey string, sealed io.Reader, size int64) (io.Reader, int64, error) {
	name, ok := clipName(id)
	if !ok {
		return nil, 0, errClipUnopened
	}
	if sentKey == "" {
		return nil, 0, errClipKeyRequired
	}
	key, err := clip.ParseKey(sentKey)
	if err != nil {
		return nil, 0, errClipKeyInvalid
	}
	if size > 0 {
		if size, err = clip.PlainSize(size); err != nil {
			return nil, 0, errClipUnopened
		}
	}
	plain, err := clip.Open(key, name, sealed)
	switch {
	case errors.Is(err, clip.ErrInvalid):
		return nil, 0, errClipKeyInvalid
	case err != nil:
		return nil, 0, errClipUnopened
	}
	return plain, size, nil
}
