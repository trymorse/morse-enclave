package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"morse/backend/internal/billing/money"
	"morse/backend/internal/routes"
)

const (
	secretsURL   = "http://10.0.0.1:8099/"
	logAddr      = "10.0.0.1:5170"
	logQueue     = 8192
	writeTimeout = 5 * time.Second
	flushTimeout = 5 * time.Second
)

type secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

var hostCredentials = []string{"COINGECKO_API_KEY", "OPENALEX_API_KEY"}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: enclave <command> [args...] | enclave --credentials <routes.json>")
	}
	if os.Args[1] == "--credentials" && len(os.Args) == 3 {
		printCredentials(os.Args[2])
		return
	}
	rts, err := routes.Load(os.Getenv("PROXY_ROUTES_FILE"), money.ListPrice)
	if err != nil {
		log.Fatal(err)
	}
	env, dropped := environ(os.Environ(), fetchSecrets(secretsURL), credentials(rts))
	logs := newShipper(logAddr, logQueue)
	shipped := make(chan struct{})
	go func() { logs.run(); close(shipped) }()
	if len(dropped) > 0 {
		line, _ := json.Marshal(map[string]any{"time": time.Now().UTC(), "level": "WARN", "msg": "enclave refused host secrets", "names": dropped})
		logs.add(line)
	}
	code := run(os.Args[1:], env, logs)
	close(logs.lines)
	select {
	case <-shipped:
	case <-time.After(flushTimeout):
	}
	os.Exit(code)
}

func fetchSecrets(url string) []secret {
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		secrets, err := getSecrets(client, url)
		if err == nil {
			return secrets
		}
		log.Printf("secrets: %v", err)
		time.Sleep(time.Second)
	}
}

func getSecrets(client *http.Client, url string) ([]secret, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	var secrets []secret
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func credentials(rts []routes.Route) []string {
	return slices.Compact(slices.Sorted(slices.Values(slices.Concat(hostCredentials, routes.KeyEnvs(rts)))))
}

func printCredentials(routesFile string) {
	rts, err := routes.Load(routesFile, money.ListPrice)
	if err != nil {
		log.Fatal(err)
	}
	for _, name := range credentials(rts) {
		fmt.Println(name)
	}
}

func environ(image []string, host []secret, credentials []string) (env, dropped []string) {
	env = slices.Clone(image)
	set := map[string]bool{}
	for _, kv := range image {
		name, _, _ := strings.Cut(kv, "=")
		set[name] = true
	}
	for _, s := range host {
		if !slices.Contains(credentials, s.Key) || set[s.Key] {
			dropped = append(dropped, s.Key)
			continue
		}
		set[s.Key] = true
		env = append(env, s.Key+"="+s.Value)
	}
	return env, dropped
}

func run(argv, env []string, logs *shipper) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	out, w, err := os.Pipe()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	w.Close()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range signals {
			cmd.Process.Signal(s)
		}
	}()
	relay(out, os.Stdout, logs)
	if err := cmd.Wait(); err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			return exit.ExitCode()
		}
		return 1
	}
	return 0
}

func relay(from io.Reader, mirror io.Writer, logs *shipper) {
	r := bufio.NewReader(from)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			mirror.Write(line)
			logs.add(line)
		}
		if err != nil {
			return
		}
	}
}

type shipper struct {
	addr    string
	lines   chan []byte
	dropped atomic.Int64
}

func newShipper(addr string, queue int) *shipper {
	return &shipper{addr: addr, lines: make(chan []byte, queue)}
}

func (s *shipper) add(line []byte) {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		line = append(line, '\n')
	}
	select {
	case s.lines <- line:
	default:
		s.dropped.Add(1)
	}
}

func (s *shipper) run() {
	var conn net.Conn
	for line := range s.lines {
		for conn == nil {
			c, err := net.DialTimeout("tcp", s.addr, writeTimeout)
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			conn = c
			if n := s.dropped.Swap(0); n > 0 {
				notice, _ := json.Marshal(map[string]any{"time": time.Now().UTC(), "level": "WARN", "msg": "enclave log lines dropped", "count": n})
				if !s.write(conn, append(notice, '\n')) {
					conn = nil
				}
			}
		}
		if !s.write(conn, line) {
			conn = nil
			s.dropped.Add(1)
		}
	}
	if conn != nil {
		conn.Close()
	}
}

func (s *shipper) write(conn net.Conn, line []byte) bool {
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write(line); err != nil {
		conn.Close()
		return false
	}
	return true
}
