package worker

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	"morse/backend/internal/e2ee/near"
)

func TestSealedHeadersAreRefusedOffE2EEAndAdmittedOnlyWithTheE2EEContract(t *testing.T) {
	none := map[string]string{}
	cases := []struct {
		name    string
		tier    catalog.Tier
		headers map[string]string
		body    string
		code    string
		sealed  bool
	}{
		{"private plain", catalog.Private, none, streamBody(""), "", false},
		{"anon plain", catalog.Anon, none, streamBody(""), "", false},
		{"tee plain", catalog.TEE, none, streamBody(""), "", false},
		{"private with seal", catalog.Private, sealHeaders, sealedBody(""), "e2ee_unsupported_model", false},
		{"tee with seal", catalog.TEE, sealHeaders, sealedBody(""), "e2ee_unsupported_model", false},
		{"tee with one header", catalog.TEE, map[string]string{e2ee.HeaderVersion: "2"}, streamBody(""), "e2ee_header_missing", false},
		{"private with legacy header", catalog.Private, map[string]string{e2ee.HeaderLegacy: "ecdsa"}, streamBody(""), "e2ee_invalid_version", false},
		{"e2ee sealed", catalog.E2EE, sealHeaders, sealedBody(""), "", true},
		{"e2ee sealed two messages", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"system","content":"` + ciphertextHex() + `"},{"role":"user","content":"` + ciphertextHex() + `"}]}`, "", true},
		{"e2ee no headers", catalog.E2EE, none, sealedBody(""), "e2ee_header_missing", false},
		{"e2ee four headers", catalog.E2EE, withMissing(e2ee.HeaderTimestamp), sealedBody(""), "e2ee_header_missing", false},
		{"e2ee legacy", catalog.E2EE, withExtra(e2ee.HeaderLegacy, "ecdsa"), sealedBody(""), "e2ee_invalid_version", false},
		{"e2ee version 1", catalog.E2EE, withExtra(e2ee.HeaderVersion, "1"), sealedBody(""), "e2ee_invalid_version", false},
		{"e2ee short nonce", catalog.E2EE, withExtra(e2ee.HeaderNonce, testNonce[:63]), sealedBody(""), "e2ee_invalid_nonce", false},
		{"e2ee bad key", catalog.E2EE, withExtra(e2ee.HeaderModelKey, "zz"), sealedBody(""), "e2ee_invalid_public_key", false},
		{"e2ee bad timestamp", catalog.E2EE, withExtra(e2ee.HeaderTimestamp, "now"), sealedBody(""), "e2ee_invalid_timestamp", false},
		{"e2ee plaintext content", catalog.E2EE, sealHeaders, streamBody(`,"max_tokens":64`), "e2ee_content_not_encrypted", false},
		{"e2ee uppercase hex content", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"user","content":"` + strings.ToUpper(ciphertextHex()) + `"}]}`, "e2ee_content_not_encrypted", false},
		{"e2ee short hex content", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"user","content":"abab"}]}`, "e2ee_content_not_encrypted", false},
		{"e2ee content parts", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"user","content":[{"type":"text","text":"` + ciphertextHex() + `"}]}]}`, "e2ee_content_not_encrypted", false},
		{"e2ee one plaintext among sealed", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"user","content":"` + ciphertextHex() + `"},{"role":"user","content":"hi"}]}`, "e2ee_content_not_encrypted", false},
		{"e2ee no messages", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[]}`, "e2ee_content_not_encrypted", false},
		{"e2ee messages absent", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64}`, "e2ee_content_not_encrypted", false},
		{"e2ee messages not a list", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":"x"}`, "e2ee_content_not_encrypted", false},
		{"e2ee message with name", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"user","name":"bob","content":"` + ciphertextHex() + `"}]}`, "e2ee_field_refused", false},
		{"e2ee message with tool_calls", catalog.E2EE, sealHeaders, `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"assistant","tool_calls":[],"content":"` + ciphertextHex() + `"}]}`, "e2ee_field_refused", false},
	}
	for field, value := range refusedOnE2EE {
		cases = append(cases, struct {
			name    string
			tier    catalog.Tier
			headers map[string]string
			body    string
			code    string
			sealed  bool
		}{"e2ee with " + field, catalog.E2EE, sealHeaders, sealedBody(`,"` + field + `":` + value), "e2ee_field_refused", false})
	}
	for _, tc := range cases {
		req, err := chat.ParseRequest(strings.NewReader(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		m := Model{Tier: tc.tier, Serves: Chat{Upstream: Plain{Provider: panickingProvider{}}}}
		if tc.tier == catalog.E2EE {
			m.Serves = Chat{Upstream: Verbatim{Route: fakeVerbatimRoute{fakeRelayer{}, fakeAttester{}, fakeReceipter{}}}}
		}
		p := protocolOf(withHeaders(tc.headers, nil))
		err = m.refuseProtocol(p)
		sealed := false
		if err == nil && tc.tier == catalog.E2EE {
			_, err = admitVerbatim(fakeRelayer{}, testSealedMaxOutput, p.params, req)
			sealed = err == nil
		}
		if sealed != tc.sealed {
			t.Errorf("%s: sealed=%t, want sealed=%t", tc.name, sealed, tc.sealed)
		}
		refusal := refusalOf(t, err)
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: refused with %s: %s", tc.name, refusal.Code, refusal.Message)
		case tc.code != "" && (refusal.Code != tc.code || refusal.Status != 400):
			t.Errorf("%s: refusal %+v, want code %s", tc.name, refusal, tc.code)
		case err != nil && strings.HasPrefix(tc.name, "e2ee with ") && !strings.Contains(refusal.Message, strings.TrimPrefix(tc.name, "e2ee with ")):
			t.Errorf("%s: message %q does not name the field", tc.name, refusal.Message)
		}
	}
}

func withMissing(name string) map[string]string {
	m := map[string]string{}
	for k, v := range sealHeaders {
		if k != name {
			m[k] = v
		}
	}
	return m
}

func withExtra(name, value string) map[string]string {
	m := map[string]string{}
	for k, v := range sealHeaders {
		m[k] = v
	}
	m[name] = value
	return m
}

func TestAdmissionRunsTheRelayersCheckLastAndMapsMismatchTo400(t *testing.T) {
	req, err := chat.ParseRequest(strings.NewReader(sealedBody("")))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		check   error
		code    string
		message string
	}{
		"accepted":       {nil, "", ""},
		"missing field":  {&chat.Mismatch{Field: "provider", Want: []byte(`{"zdr":true}`)}, "e2ee_body_mismatch", `provider must equal {"zdr":true}`},
		"unpinned field": {&chat.Mismatch{Field: "provider"}, "e2ee_field_refused", "Field provider is refused"},
		"other failure":  {errors.New("boom"), apierr.ErrInvalidBody.Code, ""},
		"refused before": {&chat.Mismatch{Field: "provider", Want: []byte(`{"zdr":true}`)}, "e2ee_field_refused", "tools"},
	}
	for name, tc := range cases {
		body := req
		if name == "refused before" {
			body, _ = chat.ParseRequest(strings.NewReader(sealedBody(`,"tools":[]`)))
		}
		_, err := admitVerbatim(fakeRelayer{tc.check}, testSealedMaxOutput, sealParams(t), body)
		refusal := refusalOf(t, err)
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: refused %+v", name, refusal)
		case tc.code != "" && (refusal.Code != tc.code || refusal.Status != 400 || !strings.Contains(refusal.Message, tc.message)):
			t.Errorf("%s: refusal %+v, want %s naming %q", name, refusal, tc.code, tc.message)
		}
	}
}

var refusedOnE2EE = map[string]string{
	"tools": `[]`, "tool_choice": `"auto"`, "logprobs": `true`, "top_logprobs": `2`,
	"prediction": `{}`, "web_search_options": `{}`, "audio": `{}`, "user": `"alice"`, "safety_identifier": `"x"`, "metadata": `{}`,
	"store": `true`, "prompt_cache_key": `"k"`, "response_format": `{"type":"json_schema","json_schema":{"name":"plaintext"}}`,
	"stop": `["plaintext"]`, "chat_template": `"{{ plaintext }}"`, "documents": `[{"text":"plaintext"}]`, "request_id": `"r"`,
	"cache_salt": `"s"`, "logit_bias": `{"1234":5}`, "best_of": `2`, "Model": `"kimi-e2ee"`, "n": `2`, "seed": `"plaintext"`,
	"temperature": `"plaintext"`, "top_p": `[1]`, "stream_options": `{"include_usage":true,"note":"plaintext"}`,
}

func TestE2EEAdmitsOnlyTheClientContractFieldsWithContentFreeValues(t *testing.T) {
	admitted := `,"max_completion_tokens":64,"temperature":0.2,"top_p":1,"frequency_penalty":-0.5,"presence_penalty":0,"seed":7,"n":1,"stream_options":{"include_usage":true},"provider":{}`
	req, err := chat.ParseRequest(strings.NewReader(sealedBody(admitted)))
	if err != nil {
		t.Fatal(err)
	}
	if asked, err := admitVerbatim(fakeRelayer{}, testSealedMaxOutput, sealParams(t), req); err != nil || asked != 64 {
		t.Errorf("the whole client contract was refused, or asked %d: %v", asked, err)
	}
	for _, role := range []string{"developer", "tool", "User", ""} {
		body := `{"model":"kimi-e2ee","max_tokens":64,"messages":[{"role":"` + role + `","content":"` + ciphertextHex() + `"}]}`
		req, err := chat.ParseRequest(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, err = admitVerbatim(fakeRelayer{}, testSealedMaxOutput, sealParams(t), req)
		if refusal := refusalOf(t, err); refusal.Code != "e2ee_field_refused" || !strings.Contains(refusal.Message, "messages.role") {
			t.Errorf("role %q: refusal %+v, want e2ee_field_refused naming messages.role", role, refusal)
		}
	}
}

func TestE2EEOutputLimitMustBeSetFitTheRouteAndAgreeBecauseTheRelayCannotSetOrLowerIt(t *testing.T) {
	for extra, code := range map[string]string{
		``:                              "e2ee_output_limit_required",
		`,"max_tokens":null`:            "e2ee_output_limit_required",
		`,"max_completion_tokens":null`: "e2ee_output_limit_required",
		`,"max_tokens":64`:              "",
		`,"max_completion_tokens":64`:   "",
		`,"max_completion_tokens":64,"max_tokens":null`: "",
		`,"max_completion_tokens":64,"max_tokens":64`:   "",
		`,"max_tokens":65`:                           "e2ee_output_limit_refused",
		`,"max_completion_tokens":262144`:            "e2ee_output_limit_refused",
		`,"max_completion_tokens":64,"max_tokens":1`: "e2ee_output_limit_refused",
		`,"max_completion_tokens":1,"max_tokens":64`: "e2ee_output_limit_refused",
	} {
		req, err := chat.ParseRequest(strings.NewReader(`{"model":"kimi-e2ee"` + extra + `,"messages":[{"role":"user","content":"` + ciphertextHex() + `"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = admitVerbatim(fakeRelayer{}, testSealedMaxOutput, sealParams(t), req)
		refusal := refusalOf(t, err)
		got := refusal.Code
		if got != code {
			t.Errorf("%s: refusal %+v, want code %q", extra, refusal, code)
		}
		if got == "e2ee_output_limit_required" && !(strings.Contains(refusal.Message, "max_tokens") && strings.Contains(refusal.Message, "max_completion_tokens")) {
			t.Errorf("%s: message %q does not name the limit fields", extra, refusal.Message)
		}
	}
}

func withNear(name, value string) map[string]string {
	m := maps.Clone(nearHeaders)
	m[name] = value
	return m
}

func TestRefuseProtocolDecidesEveryRouteShapeAgainstEveryHeaderSet(t *testing.T) {
	headers := map[string]map[string]string{
		"plaintext":        {},
		"phala":            sealHeaders,
		"phala malformed":  {e2ee.HeaderVersion: "2"},
		"phala legacy":     {e2ee.HeaderLegacy: "ecdsa"},
		"near":             nearHeaders,
		"near ecdsa":       withNear(near.HeaderSigningAlgo, "ecdsa"),
		"near v1":          withNear(near.HeaderVersion, "1"),
		"near no version":  withNear(near.HeaderVersion, ""),
		"near some fields": withNear(near.HeaderAllFields, "false"),
	}
	plain := Model{Tier: catalog.Private, Serves: Chat{Upstream: Plain{Provider: panickingProvider{}}}}
	verbatim := Model{Tier: catalog.E2EE, Serves: Chat{Upstream: Verbatim{Route: fakeVerbatimRoute{fakeRelayer{}, fakeAttester{}, fakeReceipter{}}}}}
	nearVerbatim := Model{Tier: catalog.E2EE, Serves: Chat{Upstream: Verbatim{Route: nearVerbatimRoute{fakeVerbatimRoute{fakeRelayer{}, fakeAttester{}, fakeReceipter{}}}}}}
	images := Model{Tier: catalog.Anon, Serves: Images{}}
	want := map[string]map[string]string{
		"plaintext":        {"plain": "", "verbatim": "e2ee_header_missing", "near verbatim": "e2ee_header_missing", "sealed": "e2ee_header_missing", "images": ""},
		"phala":            {"plain": "e2ee_unsupported_model", "verbatim": "", "near verbatim": "e2ee_unsupported_model", "sealed": "e2ee_unsupported_model", "images": "e2ee_unsupported_model"},
		"phala malformed":  {"plain": "e2ee_header_missing", "verbatim": "e2ee_header_missing", "near verbatim": "e2ee_unsupported_model", "sealed": "e2ee_unsupported_model", "images": "e2ee_header_missing"},
		"phala legacy":     {"plain": "e2ee_invalid_version", "verbatim": "e2ee_invalid_version", "near verbatim": "e2ee_unsupported_model", "sealed": "e2ee_unsupported_model", "images": "e2ee_invalid_version"},
		"near":             {"plain": "e2ee_unsupported_model", "verbatim": "e2ee_unsupported_model", "near verbatim": "", "sealed": "e2ee_unsupported_model", "images": "e2ee_unsupported_model"},
		"near ecdsa":       {"plain": "e2ee_invalid_algo", "verbatim": "e2ee_unsupported_model", "near verbatim": "e2ee_invalid_algo", "sealed": "e2ee_unsupported_model", "images": "e2ee_invalid_algo"},
		"near v1":          {"plain": "e2ee_invalid_version", "verbatim": "e2ee_unsupported_model", "near verbatim": "e2ee_invalid_version", "sealed": "e2ee_unsupported_model", "images": "e2ee_invalid_version"},
		"near no version":  {"plain": "e2ee_invalid_version", "verbatim": "e2ee_unsupported_model", "near verbatim": "e2ee_invalid_version", "sealed": "e2ee_unsupported_model", "images": "e2ee_invalid_version"},
		"near some fields": {"plain": "e2ee_all_fields_required", "verbatim": "e2ee_unsupported_model", "near verbatim": "e2ee_all_fields_required", "sealed": "e2ee_unsupported_model", "images": "e2ee_all_fields_required"},
	}
	wrongProtocol := map[string]bool{
		"near/verbatim": true, "near ecdsa/verbatim": true, "near v1/verbatim": true,
		"near no version/verbatim": true, "near some fields/verbatim": true, "phala/near verbatim": true,
		"phala malformed/near verbatim": true, "phala legacy/near verbatim": true,
	}
	for header, byShape := range want {
		p := protocolOf(withHeaders(headers[header], nil))
		for shape, m := range map[string]Model{"plain": plain, "verbatim": verbatim, "near verbatim": nearVerbatim, "images": images} {
			refusal := refusalOf(t, m.refuseProtocol(p))
			if refusal.Code != byShape[shape] {
				t.Errorf("%s on %s: %q, want %q", header, shape, refusal.Code, byShape[shape])
			}
			if (refusal.Message == errWrongE2EEProtocol.Message) != wrongProtocol[header+"/"+shape] {
				t.Errorf("%s on %s: wrong-protocol copy %t, message %q", header, shape, !wrongProtocol[header+"/"+shape], refusal.Message)
			}
			if header == "plaintext" && shape == "near verbatim" && refusal.Message != near.ErrHeaderMissing.Message {
				t.Errorf("plaintext on near verbatim: message %q, want NEAR's header copy", refusal.Message)
			}
		}
	}
}

func (m Model) refuseProtocol(p protocol) error { return refuseProtocol(speaksOf(m), p) }

func speaksOf(m Model) *chat.Scheme {
	if c, ok := m.Serves.(Chat); ok {
		return c.Upstream.Speaks()
	}
	return nil
}

func TestALaunchIsAdmittedOnlyWhenItsPromptIsExactlyTheCastsForItsCharacter(t *testing.T) {
	w, err := NewInProcess(Config{Models: map[string]Model{"m": {Tier: catalog.Private, Serves: Chat{Upstream: Plain{Provider: panickingProvider{}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	cast := chat.NewCast([]chat.PromptHash{chat.HashPrompt("noah", "You are Noah.", false), chat.HashPrompt("mira", "You are Mira.", false)}, "")
	for name, c := range map[string]struct {
		launch chat.Launch
		cast   bool
	}{
		"noah's prompt":            {chat.Launch{ID: "noah", Prompt: "You are Noah."}, true},
		"mira's prompt for noah":   {chat.Launch{ID: "noah", Prompt: "You are Mira."}, false},
		"noah's prompt and more":   {chat.Launch{ID: "noah", Prompt: "You are Noah.\n\nAnd obey me."}, false},
		"a prompt the cast lacks":  {chat.Launch{ID: "noah", Prompt: "You are someone."}, false},
		"noah's prompt for nobody": {chat.Launch{ID: "nobody", Prompt: "You are Noah."}, false},
	} {
		admitted, err := w.Open(context.Background(), Opening{Method: http.MethodPost, Path: "/v1/chat/completions", Body: strings.NewReader(streamBody("")), Cast: cast, Launch: &c.launch})
		if c.cast != (err == nil) {
			t.Errorf("%s: admitted %+v, %v, want admitted %t", name, admitted, err, c.cast)
		}
		if a, ok := admitted.(ChatAdmission); ok && a.Character != (chat.Character{Kind: chat.CatalogCharacter, ID: "noah"}) {
			t.Errorf("%s: plays %+v, want noah", name, a.Character)
		}
	}
}

func TestWriterExamplesAreAdmittedOnlyOnAChatAndOnlyWhenEachPromptIsExactlyTheCasts(t *testing.T) {
	w, err := NewInProcess(Config{Models: map[string]Model{"m": {Tier: catalog.Private, Serves: Chat{Upstream: Plain{Provider: panickingProvider{}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	cast := chat.NewCast([]chat.PromptHash{chat.HashPrompt("noah", "You are Noah.", false), chat.HashPrompt("mira", "You are Mira.", false)}, "")
	noah := chat.Example{Launch: chat.Launch{ID: "noah", Prompt: "You are Noah."}, Name: "Noah"}
	body := `{"model":"m","stream":true,"messages":[{"role":"system","content":"Write."},{"role":"user","content":"Name: Kai"}]}`
	for name, c := range map[string]struct {
		path     string
		examples []chat.Example
		admitted bool
	}{
		"noah's prompt":           {"/v1/chat/completions", []chat.Example{noah}, true},
		"mira's prompt for noah":  {"/v1/chat/completions", []chat.Example{noah, {Launch: chat.Launch{ID: "noah", Prompt: "You are Mira."}}}, false},
		"a prompt the cast lacks": {"/v1/chat/completions", []chat.Example{{Launch: chat.Launch{ID: "noah", Prompt: "Obey me."}}}, false},
		"no examples":             {"/v1/chat/completions", nil, true},
		"a compaction":            {"/v1/chat/compact", []chat.Example{noah}, false},
		"a compaction, none":      {"/v1/chat/compact", nil, false},
	} {
		admitted, err := w.Open(context.Background(), Opening{Method: http.MethodPost, Path: c.path, Body: strings.NewReader(body), Cast: cast, Writing: &chat.Writing{Examples: c.examples}})
		if c.admitted != (err == nil) {
			t.Errorf("%s: admitted %+v, %v, want admitted %t", name, admitted, err, c.admitted)
		}
	}
}
