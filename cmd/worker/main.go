package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"morse/backend/cmd/internal/vendors"
	"morse/backend/internal/attestation"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/door"
	"morse/backend/internal/lookup"
	"morse/backend/internal/nitro"
	"morse/backend/internal/plugins"
	"morse/backend/internal/privacyveil"
	"morse/backend/internal/routes"
	"morse/backend/internal/routesdata"
	"morse/backend/internal/seal"
	"morse/backend/internal/taskseal"
	"morse/backend/internal/tee"
	"morse/backend/internal/vendorpins"
	"morse/backend/internal/worker"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownGrace     = 30 * time.Second
	exitServeFailed   = 1
	exitBadConfig     = 2
)

type built struct {
	server     *http.Server
	inner      *worker.InProcess
	gates      *vendors.Gates
	pins       *vendorpins.Loader
	routes     int
	routesData routesdata.Checker
	door       *listeningDoor
	// filter and veil are the Privacy Veil's, when this worker serves it: in an enclave, or in dev, with a filter key.
	filter *tee.PrivacyFilter
	veil   *worker.PrivacyVeil
}

const (
	privacyFilterKeyEnv   = "TINFOIL_PRIVACY_FILTER_API_KEY"
	privacyFilterCallsEnv = "PROXY_PRIVACY_VEIL_FILTER_CALLS"
	privacyVeilCacheBytes = 64 << 20
	privacyVeilCacheTTL   = time.Hour
	privacyVeilLogEvery   = time.Minute
)

func build(getenv func(string) string, log *logger) (built, error) {
	addr := getenv("PROXY_WORKER_ADDR")
	if addr == "" {
		return built{}, errors.New("PROXY_WORKER_ADDR is required")
	}
	path := getenv("PROXY_ROUTES_FILE")
	if path == "" {
		return built{}, errors.New("PROXY_ROUTES_FILE is required")
	}
	boot, err := os.ReadFile(path)
	if err != nil {
		return built{}, fmt.Errorf("PROXY_ROUTES_FILE: %w", err)
	}
	file, err := routes.ParseFile(boot, money.ListPrice)
	if err != nil {
		return built{}, fmt.Errorf("PROXY_ROUTES_FILE: %w", err)
	}
	rts := file.Routes
	bootSum := sha256.Sum256(boot)
	digest := hex.EncodeToString(bootSum[:])
	environment := getenv("PROXY_ENVIRONMENT")
	if environment != "dev" && environment != "prod" {
		return built{}, errors.New("PROXY_ENVIRONMENT must be dev or prod, the environment the web app checks in each attestation")
	}
	attester := nitro.Open()
	if _, enclave := attester.(nitro.NSM); !enclave && environment == "prod" {
		return built{}, errors.New("PROXY_ENVIRONMENT=prod needs /dev/nsm: off an enclave the worker could attest only with a stand-in document")
	}
	identity, taskKey, err := nitro.Key(attester, getenv("PROXY_HPKE_DEV_KEY"))
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
	self := nitro.Self{Attester: attester, Identity: identity, Environment: environment}
	gate, err := door.New(environment, self, trust, floor)
	if err != nil {
		return built{}, err
	}
	tasks := taskKeys(attester, taskKey, time.Now())
	_, enclave := attester.(nitro.NSM)
	clips, receiver, err := sealedClipsOf(getenv, rts, enclave, tasks)
	if err != nil {
		return built{}, err
	}
	if receiver != nil {
		receiver.Observe = log.clipUpload
	}
	front, err := doorOf(getenv, environment, gate, identity.PublicKey(), receiver, log)
	if err != nil {
		return built{}, err
	}
	gate.ServeTaskKeys(tasks)
	mode, err := vendorpins.ParseMode(getenv("PROXY_VENDOR_PINS"))
	if err != nil {
		return built{}, fmt.Errorf("PROXY_VENDOR_PINS: %w", err)
	}
	routesMode, err := routesdata.ParseMode(getenv(routesDataEnv))
	if err != nil {
		return built{}, fmt.Errorf("%s: %w", routesDataEnv, err)
	}
	// The trusted time is the NSM attestation document's, which the host cannot move, as in the door's handoff.
	trustedTime := func(ctx context.Context) (time.Time, error) {
		document, err := gate.Attest(ctx, nil)
		if err != nil {
			return time.Time{}, err
		}
		return self.Time(document)
	}
	transport, client := vendors.NewClient()
	gates := vendors.NewGates(transport, client, attestation.NVIDIAPolicy(), log.attestation)
	pins := vendorpins.New(vendorpins.Config{
		Mode: mode, Client: client, Root: trust.Root, Identity: trust.Identity, Witnesses: trust.Witnesses, MaxAge: door.PinsMaxAge, Floor: floor,
		Now:     trustedTime,
		Observe: log.vendorPins,
		OnSwap:  gates.Wake,
	})
	unwrapped := func() { log.log(researchUnwrapped, fields{}) }
	keys, err := vendors.ReadKeys(rts, getenv)
	if err != nil {
		return built{}, err
	}
	models, err := vendors.Models(rts, keys, vendors.Deps{Client: client, Gates: gates, OnResearchUnwrapped: unwrapped})
	if err != nil {
		return built{}, err
	}
	services := lookup.Services(lookup.Keys{CoinGecko: getenv("COINGECKO_API_KEY"), OpenAlex: getenv("OPENALEX_API_KEY")})
	pluginRelay, err := pluginsIn(attester, getenv, environment)
	if err != nil {
		return built{}, err
	}
	sealingKeys, err := worker.HoldKeys(identity, tasks)
	if err != nil {
		return built{}, err
	}
	var filter *tee.PrivacyFilter
	var veil *worker.PrivacyVeil
	if getenv(privacyFilterKeyEnv) != "" && (nitro.Name(attester) == "nsm" || environment == "dev") {
		calls, err := filterCalls(getenv(privacyFilterCallsEnv))
		if err != nil {
			return built{}, err
		}
		filter = tee.NewPrivacyFilter(getenv(privacyFilterKeyEnv), tee.Deps{Base: transport, Unpinned: client, Policy: attestation.NVIDIAPolicy(), Observe: log.attestation})
		veil = &worker.PrivacyVeil{Filter: filter, Cache: privacyveil.NewCache(privacyVeilCacheBytes, privacyVeilCacheTTL, time.Now), FilterCalls: calls}
	}
	instance := rand.Text()
	inner, err := worker.NewInProcess(worker.Config{
		Models:   models,
		Retired:  file.Retired,
		Lookup:   lookup.New(services, client, time.Now),
		Plugins:  pluginRelay,
		Reports:  log,
		Sealing:  worker.Sealing{Keys: sealingKeys, Attest: gate.Attest, CacheSecret: gate.CacheSecret},
		Unpinned: gates.Unpinned,
		VendorPins: func() *worker.VendorPinsLag {
			lag, ok := pins.Lag()
			if !ok {
				return nil
			}
			return &worker.VendorPinsLag{Worker: instance, Newest: lag.Newest, Taken: lag.Taken, Behind: lag.Behind}
		},
		VendorPinsMode: string(mode),
		PrivacyVeil:    veil,
		Clips:          clips,
	})
	if err != nil {
		return built{}, err
	}
	log.names = append(append(routeNames(rts), worker.LookupPattern, seal.Endpoint), slices.Collect(maps.Keys(services))...)
	for _, rt := range seal.Routes {
		log.names = append(log.names, rt.Pattern)
	}
	for _, scope := range gates.Scopes() {
		log.names = append(log.names, scope.String())
	}
	if filter != nil {
		log.names = append(log.names, filter.Scope())
	}
	mux := http.NewServeMux()
	mux.Handle("/", worker.NewServer(inner, digest))
	gate.Register(mux)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: readHeaderTimeout, ErrorLog: discarded()}
	checker := routesDataChecker(routesMode, bootRoutes{environment: environment, file: boot, floor: floor}, trust, trustedTime, getenv, log)
	return built{server: srv, inner: inner, gates: gates, pins: pins, routes: len(models), routesData: checker, door: front, filter: filter, veil: veil}, nil
}

const taskKeyWait = 3 * time.Minute

func taskKeys(attester nitro.Attester, own *taskseal.Key, now time.Time) *taskseal.Holder {
	if _, enclave := attester.(nitro.NSM); !enclave {
		return taskseal.Settled(own, now)
	}
	held := taskseal.Pending(own, now)
	held.SettleAfter(taskKeyWait)
	return held
}

func filterCalls(value string) (int, error) {
	if value == "" {
		return worker.DefaultVeilFilterCalls, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return 0, errors.New(privacyFilterCallsEnv + " must be the most Privacy Veil filter calls the worker has in flight at once, at least 1")
	}
	return n, nil
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

func (b built) shutdown(ctx context.Context) {
	var wg sync.WaitGroup
	if b.door != nil {
		wg.Go(func() {
			if b.door.server.Shutdown(ctx) != nil {
				b.door.server.Close()
			}
		})
	}
	wg.Go(func() {
		if b.server.Shutdown(ctx) != nil {
			b.server.Close()
		}
	})
	wg.Wait()
}

// pluginsIn builds the plugins' relay only for a worker in a Nitro enclave: a plugin's call carries the user's
// token for their account at a vendor, which a process the host can read must never hold.
func pluginsIn(attester nitro.Attester, getenv func(string) string, environment string) (*plugins.Relay, error) {
	if nitro.Name(attester) != "nsm" {
		return nil, nil
	}
	return plugins.New(plugins.Servers, getenv, environment, plugins.NewClient(), time.Now)
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
	silenceStandardLogger()
	log := newLogger(os.Stderr, nil)
	w, err := build(os.Getenv, log)
	if err != nil {
		log.configFailed(err)
		os.Exit(exitBadConfig)
	}
	checkCtx, checked := context.WithTimeout(context.Background(), routesDataTimeout)
	w.routesData.Check(checkCtx)
	checked()
	gatesCtx, stopGates := context.WithCancel(context.Background())
	defer stopGates()
	w.gates.Run(gatesCtx)
	go w.pins.Run(gatesCtx)
	if w.filter != nil {
		go w.filter.Run(gatesCtx)
		go logVeilFailures(gatesCtx, w.veil, log)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		log.log(shuttingDown, fields{Duration: shutdownGrace})
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		w.shutdown(ctx)
	}()
	if w.door != nil {
		go func() {
			if err := w.door.server.ListenAndServe(w.door.addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.log(doorServeFailed, fields{})
				os.Exit(exitServeFailed)
			}
		}()
	}
	log.log(listening, fields{Count: w.routes})
	if err := w.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.log(serveFailed, fields{})
		os.Exit(exitServeFailed)
	}
	<-drained
	w.inner.Drain()
}

// logVeilFailures logs the Veils that failed each minute, as counts, so no line is timed to one request.
func logVeilFailures(ctx context.Context, veil *worker.PrivacyVeil, log *logger) {
	tick := time.NewTicker(privacyVeilLogEvery)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if counts := veil.Failures(); len(counts) > 0 {
				log.privacyVeilFailures(counts)
			}
			if counts := veil.Refusals(); len(counts) > 0 {
				log.privacyVeilRefusals(counts)
			}
			if n := veil.UnknownLabels(); n > 0 {
				log.privacyFilterLabelsUnknown(n)
			}
			log.privacyVeilReplyScans(veil.TakeReplyScans())
		case <-ctx.Done():
			return
		}
	}
}
