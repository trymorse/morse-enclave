package vendors

import (
	"fmt"
	"net/http"
	"time"

	"morse/backend/internal/anthropic"
	"morse/backend/internal/attester"
	"morse/backend/internal/audio"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/completions"
	"morse/backend/internal/fal"
	"morse/backend/internal/gemini"
	"morse/backend/internal/media"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/openairesponses"
	"morse/backend/internal/openrouter"
	"morse/backend/internal/parallel"
	"morse/backend/internal/phala"
	"morse/backend/internal/routes"
	"morse/backend/internal/runware"
	"morse/backend/internal/tee"
	"morse/backend/internal/tokenizer"
	"morse/backend/internal/upstream"
	"morse/backend/internal/venice"
	"morse/backend/internal/worker"
	"morse/backend/internal/xai"
)

const (
	responseHeaderTimeout = 2 * time.Minute
	maxIdleConnsPerHost   = 64
)

func NewClient() (*http.Transport, *http.Client) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	return transport, &http.Client{Transport: transport}
}

type Deps struct {
	Client              *http.Client
	Gates               *Gates
	OnResearchUnwrapped func(runID string)
}

type builder[S routes.Serves] func(rt routes.Route, s S, key string, d Deps) (worker.Serving, error)

type build func(rt routes.Route, key string, d Deps) (worker.Serving, error)

func erase[S routes.Serves](b builder[S]) build {
	return func(rt routes.Route, key string, d Deps) (worker.Serving, error) { return b(rt, rt.Serves.(S), key, d) }
}

var chatProviders = map[routes.Provider]newChatProvider{
	routes.ProviderOpenAI:          openAIProvider,
	routes.ProviderOpenAIResponses: translating(openairesponses.New),
	routes.ProviderAnthropic:       translating(anthropic.New),
	routes.ProviderGemini:          translating(gemini.NewChat),
	routes.ProviderXAI:             xaiProvider,
	routes.ProviderOpenRouter:      openRouterProvider,
	routes.ProviderVenice:          veniceProvider,
}

var builders = withChat(map[routes.Provider]map[catalog.Kind]build{
	routes.ProviderOpenAI:  {catalog.KindTranscription: erase(openAITranscription)},
	routes.ProviderGemini:  {catalog.KindImage: erase(imagesBy(gemini.NewImages))},
	routes.ProviderXAI:     {catalog.KindImage: erase(imagesBy(xai.NewImages)), catalog.KindVideo: erase(videosBy(xai.NewVideos))},
	routes.ProviderRunware: {catalog.KindImage: erase(imagesBy(runware.NewImages)), catalog.KindVideo: erase(videosBy(runware.NewVideos))},
	routes.ProviderFal:     {catalog.KindImage: erase(imagesBy(fal.NewImages)), catalog.KindVideo: erase(videosBy(fal.NewVideos))},
	routes.ProviderVenice:  {catalog.KindImage: erase(imagesBy(venice.NewImages))},
	routes.ProviderParallel: {
		catalog.KindSearch:   erase(parallelSearch),
		catalog.KindFetch:    erase(parallelFetch),
		catalog.KindResearch: erase(parallelResearch),
	},
})

func withChat(m map[routes.Provider]map[catalog.Kind]build) map[routes.Provider]map[catalog.Kind]build {
	for p, newProvider := range chatProviders {
		if m[p] == nil {
			m[p] = map[catalog.Kind]build{}
		}
		m[p][catalog.KindChat] = erase(chatBy(newProvider))
	}
	return m
}

// ChatProvider is the provider the proxy sends rt's plaintext chats through, without the busy retry and the serving
// around it, for a tool that sends single calls and reads each reply as the proxy would. An attested route's gateway
// is reached in the clear and unattested, which only Phala serves.
func ChatProvider(rt routes.Route, key string, client *http.Client) (chat.Provider, error) {
	if up, attested := rt.Upstream.(routes.Attested); attested {
		if up.Attester != attester.Phala {
			return nil, fmt.Errorf("route %q: %s serves no plaintext chat", rt.Model, up.Attester.Name)
		}
		return phala.New(rt.BaseURL, rt.UpstreamModel, key, phala.Clients{Plaintext: client, Sealed: client}, nil), nil
	}
	c, isChat := routes.ChatOf(rt.Serves)
	newProvider := chatProviders[rt.Upstream.(routes.Vendor).Provider]
	if !isChat || newProvider == nil {
		return nil, fmt.Errorf("route %q is no chat route a provider serves", rt.Model)
	}
	return newProvider(rt, c, key, Deps{Client: client}), nil
}

func Build(rt routes.Route, key string, d Deps) (worker.Serving, error) {
	if up, attested := rt.Upstream.(routes.Attested); attested && rt.Serves.Kind() == catalog.KindTranscription {
		return attestedTranscription(rt, up, key, d)
	}
	if up, attested := rt.Upstream.(routes.Attested); attested {
		return attestedChat(rt, up, key, d)
	}
	return builders[rt.Upstream.(routes.Vendor).Provider][rt.Serves.Kind()](rt, key, d)
}

func Attester(rt routes.Route) string {
	if up, attested := rt.Upstream.(routes.Attested); attested {
		return up.Attester.Name
	}
	return ""
}

type Keys map[string]string

func ReadKeys(rts []routes.Route, getenv func(string) string) (Keys, error) {
	keys := Keys{}
	for _, name := range routes.KeyEnvs(rts) {
		key := getenv(name)
		if key == "" {
			return nil, fmt.Errorf("routes.json names api_key_env %s, which is unset", name)
		}
		keys[name] = key
	}
	return keys, nil
}

func Models(rts []routes.Route, keys Keys, d Deps) (map[string]worker.Model, error) {
	models := make(map[string]worker.Model, len(rts))
	for _, rt := range rts {
		m, err := model(rt, keys, d)
		if err != nil {
			return nil, err
		}
		models[rt.Model] = m
	}
	return models, nil
}

func model(rt routes.Route, keys Keys, d Deps) (worker.Model, error) {
	serves, err := Build(rt, keys[rt.APIKeyEnv], d)
	if err != nil {
		return worker.Model{}, err
	}
	m := worker.Model{Tier: rt.Tier, Attester: Attester(rt), Serves: serves}
	for _, fb := range rt.Fallbacks {
		f, err := model(fb, keys, d)
		if err != nil {
			return worker.Model{}, err
		}
		m.Fallbacks = append(m.Fallbacks, f)
	}
	return m, nil
}

var limitFields = map[catalog.Tier]openaicompat.LimitField{catalog.Anon: openaicompat.MaxCompletionTokens, catalog.Private: openaicompat.MaxTokens}

func chatServed(rt routes.Route, c routes.Chat) (worker.Chat, error) {
	served := worker.Chat{ChatTerms: c.ChatTerms}
	if c.Tokenizer == "" {
		return served, nil
	}
	counter, err := tokenizer.Load(c.Tokenizer)
	if err != nil {
		return worker.Chat{}, fmt.Errorf("route %q names %w", rt.Model, err)
	}
	served.Counter = counter
	return served, nil
}

type newChatProvider func(rt routes.Route, c routes.Chat, key string, d Deps) chat.Provider

func chatBy(newProvider newChatProvider) builder[routes.Chat] {
	return func(rt routes.Route, c routes.Chat, key string, d Deps) (worker.Serving, error) {
		served, err := chatServed(rt, c)
		if err != nil {
			return nil, err
		}
		served.Upstream = worker.Plain{Provider: newProvider(rt, c, key, d), BusyWaits: chat.BusyWaits, Hedge: hedgeFor(rt)}
		served.Reasoning, served.ReasoningUncapped = rt.Upstream.(routes.Vendor).Provider.Reasoning(c.ReasoningEfforts), rt.ReasoningUncapped()
		return served, nil
	}
}

func hedgeFor(rt routes.Route) chat.Hedge {
	if rt.Hedgeable() {
		return chat.DefaultHedge
	}
	return chat.Hedge{}
}

func openAIProvider(rt routes.Route, _ routes.Chat, key string, d Deps) chat.Provider {
	sender := openaicompat.HTTPSender{Endpoint: upstream.Endpoint{BaseURL: rt.BaseURL, Auth: upstream.Bearer(key), HTTP: d.Client}}
	return &openaicompat.Provider{Sender: sender, Model: rt.UpstreamModel, LimitField: limitFields[rt.Tier]}
}

func translating(newProvider func(baseURL, key, model string, client *http.Client) *completions.Provider) newChatProvider {
	return func(rt routes.Route, _ routes.Chat, key string, d Deps) chat.Provider {
		return newProvider(rt.BaseURL, key, rt.UpstreamModel, d.Client)
	}
}

func xaiProvider(rt routes.Route, _ routes.Chat, key string, d Deps) chat.Provider {
	return xai.NewChat(rt.BaseURL, key, rt.UpstreamModel, rt.Retention, d.Client)
}

func openRouterProvider(rt routes.Route, c routes.Chat, key string, d Deps) chat.Provider {
	return openrouter.NewChat(rt.BaseURL, key, rt.UpstreamModel, c.Price, d.Client)
}

func veniceProvider(rt routes.Route, _ routes.Chat, key string, d Deps) chat.Provider {
	return venice.NewChat(rt.BaseURL, key, rt.UpstreamModel, d.Client)
}

func attestedChat(rt routes.Route, attested routes.Attested, key string, d Deps) (worker.Serving, error) {
	up := attester.Upstream{BaseURL: rt.BaseURL, Host: rt.Host, Model: rt.UpstreamModel, APIKey: key}
	gate, err := d.Gates.gate(rt.Model, attested.Attester, up)
	if err != nil {
		return nil, err
	}
	served, err := chatServed(rt, rt.Serves.(routes.Chat))
	if err != nil {
		return nil, err
	}
	if !rt.Tier.Sealed() {
		plain, serves := gate.Plain(up)
		if !serves {
			return nil, fmt.Errorf("route %q is tier %s, and %s serves no plaintext", rt.Model, rt.Tier, attested.Attester.Name)
		}
		served.Upstream = worker.Plain{Provider: plain, Attester: plain, Hedge: hedgeFor(rt)}
		return served, nil
	}
	served.Upstream = worker.Verbatim{Route: gate.Route(up)}
	return served, nil
}

func attestedTranscription(rt routes.Route, attested routes.Attested, key string, d Deps) (worker.Serving, error) {
	if !attested.Attester.Transcribes() {
		return nil, fmt.Errorf("route %q is of kind %s, and %s serves no transcription", rt.Model, rt.Serves.Kind(), attested.Attester.Name)
	}
	up := attester.Upstream{BaseURL: rt.BaseURL, Host: rt.Host, Model: rt.UpstreamModel, APIKey: key}
	gate, err := d.Gates.gate(rt.Model, attested.Attester, up)
	if err != nil {
		return nil, err
	}
	transcriber := gate.(tee.Transcribing).Transcriber(up)
	return worker.Transcription{Transcriber: transcriber, Attester: transcriber}, nil
}

func openAITranscription(rt routes.Route, _ routes.PerCall, key string, d Deps) (worker.Serving, error) {
	return worker.Transcription{Transcriber: audio.NewOpenAI(rt.BaseURL, key, rt.UpstreamModel, d.Client)}, nil
}

type newGenerator[G any] func(baseURL, apiKey, model string, client *http.Client) (G, error)

func imagesBy[G media.ImageGenerator](newGen newGenerator[G]) builder[routes.Image] {
	return func(rt routes.Route, _ routes.Image, key string, d Deps) (worker.Serving, error) {
		gen, err := newGen(rt.BaseURL, key, rt.UpstreamModel, d.Client)
		if err != nil {
			return nil, upstreamModelError(rt, err)
		}
		return worker.Images{ImageGenerator: gen}, nil
	}
}

func videosBy[G media.VideoGenerator](newGen newGenerator[G]) builder[routes.Video] {
	return func(rt routes.Route, _ routes.Video, key string, d Deps) (worker.Serving, error) {
		gen, err := newGen(rt.BaseURL, key, rt.UpstreamModel, d.Client)
		if err != nil {
			return nil, upstreamModelError(rt, err)
		}
		return worker.Videos{VideoGenerator: gen}, nil
	}
}

func parallelSearch(rt routes.Route, _ routes.PerCall, key string, d Deps) (worker.Serving, error) {
	searcher, err := parallel.NewSearch(rt.BaseURL, key, rt.UpstreamModel, d.Client)
	if err != nil {
		return nil, upstreamModelError(rt, err)
	}
	return worker.Search{Searcher: searcher}, nil
}

func parallelFetch(rt routes.Route, _ routes.PerCall, key string, d Deps) (worker.Serving, error) {
	fetcher, err := parallel.NewExtract(rt.BaseURL, key, rt.UpstreamModel, d.Client)
	if err != nil {
		return nil, upstreamModelError(rt, err)
	}
	return worker.Fetch{Fetcher: fetcher}, nil
}

func parallelResearch(rt routes.Route, _ routes.PerCall, key string, d Deps) (worker.Serving, error) {
	unwrapped := d.OnResearchUnwrapped
	if unwrapped == nil {
		unwrapped = func(string) {}
	}
	researcher, err := parallel.NewResearch(rt.BaseURL, key, rt.UpstreamModel, d.Client, unwrapped)
	if err != nil {
		return nil, upstreamModelError(rt, err)
	}
	return worker.Research{Researcher: researcher}, nil
}

func upstreamModelError(rt routes.Route, err error) error {
	return fmt.Errorf("route %q upstream_model %w", rt.Model, err)
}
