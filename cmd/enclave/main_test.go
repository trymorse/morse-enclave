package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/routes"
)

var imageSettings = []string{"PROXY_WORKER_ADDR", "PROXY_ROUTES_FILE", "PROXY_ENVIRONMENT", "PROXY_DOOR_FLOOR", "PROXY_VENDOR_PINS"}

var neverInAnImage = []string{"PROXY_HPKE_DEV_KEY"}

func TestTheHostSetsOnlyCredentialsAndTheImagesValuesWin(t *testing.T) {
	image := []string{"PROXY_ROUTES_FILE=/routes.json", "AUTH_URL=https://auth.example"}
	host := []secret{
		{"PHALA_API_KEY", "k"},
		{"DATABASE_URL", "postgres://db"},
		{"AUTH_URL", "https://evil.example"},
		{"STORAGE_URL", "https://evil.example"},
		{"SSL_CERT_FILE", "/evil.pem"},
		{"HTTPS_PROXY", "http://evil"},
		{"GODEBUG", "x509ignoreCN=1"},
		{"PROXY_ROUTES_FILE", "/evil.json"},
		{"DATABASE_URL_DIRECT", "postgres://direct"},
		{"ALERTS_TOKEN", "x"},
		{"PROXY_HPKE_DEV_KEY", "00"},
	}
	env, dropped := environ(image, host, []string{"PHALA_API_KEY", "DATABASE_URL"})
	want := []string{"PROXY_ROUTES_FILE=/routes.json", "AUTH_URL=https://auth.example", "PHALA_API_KEY=k", "DATABASE_URL=postgres://db"}
	if !slices.Equal(env, want) {
		t.Errorf("env = %q, want %q", env, want)
	}
	if len(dropped) != len(host)-2 {
		t.Errorf("dropped %q, want every host name but the two credentials", dropped)
	}
}

func TestTheHostsFirstValueForACredentialWins(t *testing.T) {
	env, dropped := environ(nil, []secret{{"COINGECKO_API_KEY", "a"}, {"COINGECKO_API_KEY", "b"}}, hostCredentials)
	if !slices.Equal(env, []string{"COINGECKO_API_KEY=a"}) || !slices.Equal(dropped, []string{"COINGECKO_API_KEY"}) {
		t.Errorf("env %q dropped %q", env, dropped)
	}
}

func TestTheRelaysOwnSecretsNeverReachTheWorker(t *testing.T) {
	rts, err := routes.Load("../../routes.json", money.ListPrice)
	if err != nil {
		t.Fatal(err)
	}
	relay := []secret{{"AT_REST_KEY", "a"}, {"AT_REST_KEY_2", "b"}, {"DATABASE_URL", "postgres://db"}, {"PAYMENTS_SECRET_KEY", "sk"}, {"IP_HASH_KEY", "g"}, {"STORAGE_SECRET_KEY", "v"}}
	env, dropped := environ(nil, relay, credentials(rts))
	if len(env) != 0 || len(dropped) != len(relay) {
		t.Errorf("env %q dropped %q; want every relay secret dropped", env, dropped)
	}
}

func TestTheCredentialsTheHostMayServeAreExactlyThoseTheEnclaveKeeps(t *testing.T) {
	rts, err := routes.Load("../../routes.json", money.ListPrice)
	if err != nil {
		t.Fatal(err)
	}
	names := credentials(rts)
	if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
		t.Errorf("credentials %q are not sorted and unique", names)
	}
	for _, name := range slices.Concat(hostCredentials, routes.KeyEnvs(rts)) {
		if !slices.Contains(names, name) {
			t.Errorf("%s is kept by the enclave but missing from credentials", name)
		}
	}
	for _, name := range []string{"DATABASE_URL", "AT_REST_KEY", "PAYMENTS_SECRET_KEY"} {
		if slices.Contains(names, name) {
			t.Errorf("credentials lists %s", name)
		}
	}
}

func TestEveryRoutesKeyIsACredential(t *testing.T) {
	rts, err := routes.Load("../../routes.json", money.ListPrice)
	if err != nil {
		t.Fatal(err)
	}
	keys := routes.KeyEnvs(rts)
	for _, want := range []string{"PHALA_API_KEY", "NEAR_API_KEY", "ANTHROPIC_API_KEY"} {
		if !slices.Contains(keys, want) {
			t.Errorf("route keys %q lack %s", keys, want)
		}
	}
}

var envName = regexp.MustCompile(`"([A-Z][A-Z0-9]*_[A-Z0-9_]*)"`)

func TestEveryVariableTheWorkerReadsIsACredentialOrAnImageSettingAndTheHostSuppliesNoOther(t *testing.T) {
	files, _ := filepath.Glob("../worker/*.go")
	read := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range envName.FindAllSubmatch(src, -1) {
			name := string(m[1])
			read[name] = true
			listed := 0
			for _, list := range [][]string{hostCredentials, imageSettings, neverInAnImage} {
				if slices.Contains(list, name) {
					listed++
				}
			}
			if listed != 1 {
				t.Errorf("%s reads %s; list it in hostCredentials in main.go if the host may supply it, in imageSettings here and in deploy/enclave/*.env if the image sets it, or in neverInAnImage if neither may", f, name)
			}
		}
	}
	if len(read) == 0 {
		t.Fatal("found no variable names in cmd/worker")
	}
	for _, name := range slices.Concat(hostCredentials, imageSettings, neverInAnImage) {
		if !read[name] {
			t.Errorf("the enclave lets the host or the image set %s, which cmd/worker never reads", name)
		}
	}
}

func TestEachEnvironmentsImageSetsOnlyImageSettings(t *testing.T) {
	files, _ := filepath.Glob("../../deploy/enclave/*.env")
	if len(files) == 0 {
		t.Fatal("no deploy/enclave/*.env")
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(src)), "\n") {
			name, value, ok := strings.Cut(line, "=")
			if !ok || value == "" || strings.ContainsAny(value, " \t\"'") {
				t.Errorf("%s: %q is not NAME=value with no spaces or quotes", f, line)
			}
			known := slices.Contains(imageSettings, name)
			if !known || slices.Contains(hostCredentials, name) {
				t.Errorf("%s sets %s, which is not an image setting", f, name)
			}
		}
	}
}

// namesItsEnvironment refuses an image's env file unless it sets
// PROXY_ENVIRONMENT to its own environment on exactly one line. A second line
// would override the first, because build.sh turns each line into an ENV.
func namesItsEnvironment(environment, src string) error {
	var set []string
	for _, line := range strings.Split(strings.TrimSpace(src), "\n") {
		if name, value, _ := strings.Cut(line, "="); name == "PROXY_ENVIRONMENT" {
			set = append(set, value)
		}
	}
	if len(set) != 1 || set[0] != environment {
		return fmt.Errorf("sets PROXY_ENVIRONMENT to %q, want %s on exactly one line", set, environment)
	}
	return nil
}

func TestEachEnvironmentsImageNamesItsOwnEnvironment(t *testing.T) {
	files, _ := filepath.Glob("../../deploy/enclave/*.env")
	if len(files) == 0 {
		t.Fatal("no deploy/enclave/*.env")
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := namesItsEnvironment(strings.TrimSuffix(filepath.Base(f), ".env"), string(src)); err != nil {
			t.Errorf("%s %v", f, err)
		}
	}
	prod := "PROXY_WORKER_ADDR=0.0.0.0:8080\nPROXY_ENVIRONMENT=prod\n"
	for name, src := range map[string]string{
		"names dev":      strings.Replace(prod, "=prod", "=dev", 1),
		"names it twice": prod + "PROXY_ENVIRONMENT=prod\n",
		"overrides it":   prod + "PROXY_ENVIRONMENT=dev\n",
		"never names it": "PROXY_WORKER_ADDR=0.0.0.0:8080\n",
	} {
		if namesItsEnvironment("prod", src) == nil {
			t.Errorf("a prod.env that %s passes", name)
		}
	}
	if err := namesItsEnvironment("prod", prod); err != nil {
		t.Errorf("a prod.env that names prod once is refused: %v", err)
	}
}

func TestNoEnvironmentsImageSetsTheDevKey(t *testing.T) {
	files, _ := filepath.Glob("../../deploy/enclave/*.env")
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range neverInAnImage {
			if strings.Contains(string(src), name+"=") {
				t.Errorf("%s sets %s, which no enclave image may", f, name)
			}
		}
	}
}

func TestSecretsAreRetriedUntilTheHostServesThem(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls++; calls == 1 {
			http.Error(w, "not yet", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`[{"key":"PHALA_API_KEY","value":"k"}]`))
	}))
	defer srv.Close()
	if got := fetchSecrets(srv.URL); !slices.Equal(got, []secret{{"PHALA_API_KEY", "k"}}) || calls != 2 {
		t.Errorf("got %v after %d calls", got, calls)
	}
}

func TestAFullQueueDropsLinesWithoutBlockingAndTheHostLearnsHowMany(t *testing.T) {
	s := newShipper("", 2)
	done := make(chan struct{})
	go func() {
		for i := range 5 {
			s.add([]byte{'a' + byte(i)})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("add blocked with no host to ship to")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s.addr = ln.Addr().String()
	go s.run()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	var notice struct {
		Msg   string `json:"msg"`
		Count int    `json:"count"`
	}
	first, _ := r.ReadBytes('\n')
	if err := json.Unmarshal(first, &notice); err != nil || notice.Msg != "enclave log lines dropped" || notice.Count != 3 {
		t.Errorf("first line %q, want a notice that 3 lines were dropped", first)
	}
	for _, want := range []string{"a\n", "b\n"} {
		if got, _ := r.ReadString('\n'); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestTheCommandsOutputReachesTheHostAndItsExitCodeIsKept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := newShipper(ln.Addr().String(), 16)
	go s.run()
	lines := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(conn)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			lines <- l
		}
	}()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	stdout := os.Stdout
	os.Stdout = devnull
	code := run([]string{sh, "-c", `echo "{\"msg\":\"out $SECRET\"}"; echo err >&2; exit 7`}, []string{"SECRET=s"}, s)
	os.Stdout = stdout
	if code != 7 {
		t.Errorf("exit code %d, want 7", code)
	}
	var got []string
	for range 2 {
		select {
		case l := <-lines:
			got = append(got, strings.TrimSpace(l))
		case <-time.After(5 * time.Second):
			t.Fatalf("host got %q", got)
		}
	}
	slices.Sort(got)
	if want := []string{`err`, `{"msg":"out s"}`}; !slices.Equal(got, want) {
		t.Errorf("host got %q, want %q", got, want)
	}
}
