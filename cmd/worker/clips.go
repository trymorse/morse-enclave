package main

import (
	"fmt"
	"net/http"

	"morse/backend/internal/clip"
	"morse/backend/internal/routes"
	"morse/backend/internal/taskseal"
	"morse/backend/internal/worker"
)

const (
	clipOriginEnv = "PROXY_CLIP_UPLOAD_ORIGIN"
	clipStoreEnv  = "PROXY_CLIP_STORE_URL"
)

func sealedClipsOf(getenv func(string) string, rts []routes.Route, enclave bool, tasks *taskseal.Holder) (*worker.SealedClips, *clip.Receiver, error) {
	rawOrigin, rawStore := getenv(clipOriginEnv), getenv(clipStoreEnv)
	if rawOrigin == "" && rawStore == "" {
		if uploaders := routes.VideoUploaders(rts); enclave && len(uploaders) > 0 {
			return nil, nil, fmt.Errorf("route %q has its vendor write each clip into the video store itself, which an enclave serves only with %s and %s set, so the clip reaches the store sealed", uploaders[0], clipOriginEnv, clipStoreEnv)
		}
		return nil, nil, nil
	}
	if rawOrigin == "" || rawStore == "" {
		return nil, nil, fmt.Errorf("%s and %s go together: the door's origin the vendor uploads each clip to, and the bucket the door stores it in sealed", clipOriginEnv, clipStoreEnv)
	}
	origin, err := clip.ParseOrigin(clipOriginEnv, rawOrigin)
	if err != nil {
		return nil, nil, err
	}
	store, err := clip.ParseStore(clipStoreEnv, rawStore)
	if err != nil {
		return nil, nil, err
	}
	if getenv("PROXY_DOOR_ADDR") == "" {
		return nil, nil, fmt.Errorf("%s needs PROXY_DOOR_ADDR: the vendor's upload lands on the door, which seals it", clipOriginEnv)
	}
	tickets := ticketKeysOf(tasks)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &worker.SealedClips{Origin: origin, Store: store, Tickets: tickets}, clip.NewReceiver(store, tickets, transport), nil
}

func ticketKeysOf(tasks *taskseal.Holder) clip.TicketKeys {
	return func() (*clip.TicketKey, bool) {
		secret, _, settled := tasks.Held()
		if !settled {
			return nil, false
		}
		epoch, _ := tasks.State()
		key, err := clip.NewTicketKey(secret, epoch)
		return key, err == nil
	}
}
