package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"morse/backend/cmd/internal/vendors"
	"morse/backend/internal/attestation"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/door"
	"morse/backend/internal/lookup"
	"morse/backend/internal/nitro"
	"morse/backend/internal/routes"
	"morse/backend/internal/worker"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownGrace     = 30 * time.Second
	exitServeFailed   = 1
	exitBadConfig     = 2
)

type built struct {
	server *http.Server
	inner  *worker.InProcess
	gates  *vendors.Gates
	routes int
}

func build(getenv func(string) string, log *logger) (built, error) {
	addr := getenv("PROXY_WORKER_ADDR")
	if addr == "" {
		return built{}, errors.New("PROXY_WORKER_ADDR is required")
	}
	path := getenv("PROXY_ROUTES_FILE")
	if path == "" {
		return built{}, errors.New("PROXY_ROUTES_FILE is required")
	}
	rts, digest, err := routes.Read(path, money.ListPrice)
	if err != nil {
		return built{}, fmt.Errorf("PROXY_ROUTES_FILE: %w", err)
	}
	environment := getenv("PROXY_ENVIRONMENT")
	if environment != "dev" && environment != "prod" {
		return built{}, errors.New("PROXY_ENVIRONMENT must be dev or prod, the environment the web app checks in each attestation")
	}
	attester := nitro.Open()
	if _, enclave := attester.(nitro.NSM); !enclave && environment == "prod" {
		return built{}, errors.New("PROXY_ENVIRONMENT=prod needs /dev/nsm: off an enclave the worker could attest only with a stand-in document")
	}
	identity, err := nitro.Key(attester, getenv("PROXY_HPKE_DEV_KEY"))
	if err != nil {
		return built{}, err
	}
	trust, err := door.Production()
	if err != nil {
		return built{}, err
	}
	floor, err := doorFloor(getenv("PROXY_DOOR_FLOOR"), environment)
	if err != nil {
		return built{}, err
	}
	gate, err := door.New(environment, nitro.Self{Attester: attester, Identity: identity, Environment: environment}, trust, floor)
	if err != nil {
		return built{}, err
	}
	transport, client := vendors.NewClient()
	gates := vendors.NewGates(transport, client, attestation.NVIDIAPolicy(), log.attestation)
	unwrapped := func(string) { log.log(researchUnwrapped, fields{}) }
	keys, err := vendors.ReadKeys(rts, getenv)
	if err != nil {
		return built{}, err
	}
	models, err := vendors.Models(rts, keys, vendors.Deps{Client: client, Gates: gates, OnResearchUnwrapped: unwrapped})
	if err != nil {
		return built{}, err
	}
	services := lookup.Services(lookup.Keys{CoinGecko: getenv("COINGECKO_API_KEY"), OpenAlex: getenv("OPENALEX_API_KEY")})
	inner, err := worker.NewInProcess(worker.Config{
		Models:  models,
		Lookup:  lookup.New(services, client, time.Now),
		Reports: log,
		Sealing: worker.Sealing{Identity: identity, Attest: gate.Attest},
	})
	if err != nil {
		return built{}, err
	}
	log.names = append(append(routeNames(rts), worker.LookupPattern), slices.Collect(maps.Keys(services))...)
	for _, scope := range gates.Scopes() {
		log.names = append(log.names, scope.String())
	}
	mux := http.NewServeMux()
	mux.Handle("/", worker.NewServer(inner, digest))
	gate.Register(mux)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: readHeaderTimeout, ErrorLog: discarded()}
	return built{server: srv, inner: inner, gates: gates, routes: len(models)}, nil
}

func doorFloor(value, environment string) (uint64, error) {
	if value == "" && environment == "dev" {
		return 0, nil
	}
	floor, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("PROXY_DOOR_FLOOR must be the pins statement sequence the image was built at, the lowest a handoff admits")
	}
	return floor, nil
}

func routeNames(rts []routes.Route) []string {
	var names []string
	for _, served := range rts {
		for _, rt := range served.Upstreams() {
			names = append(names, rt.Model)
		}
	}
	return names
}

func main() {
	log := newLogger(os.Stderr, nil)
	w, err := build(os.Getenv, log)
	if err != nil {
		log.configFailed(err)
		os.Exit(exitBadConfig)
	}
	gatesCtx, stopGates := context.WithCancel(context.Background())
	defer stopGates()
	w.gates.Run(gatesCtx)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		log.log(shuttingDown, fields{Duration: shutdownGrace})
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if w.server.Shutdown(ctx) != nil {
			w.server.Close()
		}
	}()
	log.log(listening, fields{Count: w.routes})
	if err := w.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.log(serveFailed, fields{})
		os.Exit(exitServeFailed)
	}
	<-drained
	w.inner.Drain()
}
