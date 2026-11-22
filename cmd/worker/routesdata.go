package main

import (
	"context"
	"net/http"
	"time"

	"morse/backend/cmd/internal/vendors"
	"morse/backend/internal/attestation"
	"morse/backend/internal/attested"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/door"
	"morse/backend/internal/routes"
	"morse/backend/internal/routesdata"
)

const (
	routesDataEnv      = "PROXY_ROUTES_DATA"
	routesDataTimeout  = 15 * time.Second
	routesOfferTimeout = 5 * time.Second
)

var routesOfferURL = routesdata.OfferURL

type bootRoutes struct {
	environment string
	file        []byte
	floor       uint64
}

func routesDataChecker(mode routesdata.Mode, boot bootRoutes, trust door.Trust, now func(context.Context) (time.Time, error), getenv func(string) string, log *logger) routesdata.Checker {
	host := &http.Client{Timeout: routesOfferTimeout}
	url := routesOfferURL
	return routesdata.Checker{
		Mode: mode,
		Image: routesdata.Image{
			Environment: boot.environment,
			Boot:        boot.file,
			Floor:       boot.floor,
			MaxAge:      routesdata.MaxAge,
			Trust:       routesdata.Trust{Root: trust.Root, Identity: trust.Identity, Witnesses: trust.Witnesses},
			Load:        workerLoads(getenv),
		},
		Fetch:   func(ctx context.Context) (routesdata.Offer, error) { return routesdata.Fetch(ctx, host, url) },
		Now:     now,
		Observe: log.routesData,
	}
}

func workerLoads(getenv func(string) string) func([]byte) error {
	return func(file []byte) error {
		parsed, err := routes.ParseFile(file, money.ListPrice)
		if err != nil {
			return err
		}
		keys, err := vendors.ReadKeys(parsed.Routes, getenv)
		if err != nil {
			return err
		}
		transport, client := vendors.NewClient()
		gates := vendors.NewGates(transport, client, attestation.NVIDIAPolicy(), func(attested.Event) {})
		_, err = vendors.Models(parsed.Routes, keys, vendors.Deps{Client: client, Gates: gates, OnResearchUnwrapped: func() {}})
		return err
	}
}
