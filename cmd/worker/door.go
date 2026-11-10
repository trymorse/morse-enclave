package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"morse/backend/internal/baseurl"
	"morse/backend/internal/door"
)

type listeningDoor struct {
	addr   string
	server *door.Server
}

func doorOf(getenv func(string) string, environment string, gate *door.Door, sealTo []byte, log *logger) (*listeningDoor, error) {
	addr := getenv("PROXY_DOOR_ADDR")
	if addr == "" {
		return nil, nil
	}
	raw := getenv("PROXY_DOOR_RELAY_URL")
	if raw == "" {
		return nil, errors.New("PROXY_DOOR_RELAY_URL is required with PROXY_DOOR_ADDR: the relay the door hands each request to, such as http://10.0.0.1:8080")
	}
	relay, err := baseurl.ParseAllowingPlain("PROXY_DOOR_RELAY_URL", "http://10.0.0.1:8080", raw, "10.0.0.1")
	if err != nil {
		return nil, err
	}
	raw = getenv("PROXY_DOOR_PROXY_PROTOCOL")
	if raw == "" {
		return nil, errors.New("PROXY_DOOR_PROXY_PROTOCOL is required with PROXY_DOOR_ADDR: on behind the NLB, which names each client in a PROXY v2 header, or off when clients reach the door directly")
	}
	proxied, err := parseSwitch("PROXY_DOOR_PROXY_PROTOCOL", raw)
	if err != nil {
		return nil, err
	}
	if environment == "prod" && !proxied {
		return nil, errors.New("PROXY_DOOR_PROXY_PROTOCOL=off in prod would let any peer name the client's address; prod sits behind the NLB and needs on")
	}
	peers, err := proxyPeers(getenv("PROXY_DOOR_PROXY_PEERS"), proxied)
	if err != nil {
		return nil, err
	}
	server, err := door.NewServer(door.Config{Door: gate, SealTo: sealTo, Relay: relay, RequireProxyV2: proxied, ProxyPeers: peers, Reports: log})
	if err != nil {
		return nil, err
	}
	return &listeningDoor{addr: addr, server: server}, nil
}

func proxyPeers(raw string, proxied bool) ([]netip.Prefix, error) {
	if raw == "" {
		if proxied {
			return nil, errors.New("PROXY_DOOR_PROXY_PEERS is required with PROXY_DOOR_PROXY_PROTOCOL=on: the NLB's subnets, such as 10.40.0.0/20,10.40.16.0/20; with none the door trusts no peer and closes every connection")
		}
		return nil, nil
	}
	if !proxied {
		return nil, errors.New("PROXY_DOOR_PROXY_PEERS is set with PROXY_DOOR_PROXY_PROTOCOL=off; the peers it names send PROXY v2 headers the door would not read")
	}
	var peers []netip.Prefix
	for _, field := range strings.Split(raw, ",") {
		peer, err := netip.ParsePrefix(strings.TrimSpace(field))
		if err != nil {
			return nil, fmt.Errorf("PROXY_DOOR_PROXY_PEERS must list CIDR ranges, such as 10.40.0.0/20,10.40.16.0/20: %w", err)
		}
		peers = append(peers, peer.Masked())
	}
	return peers, nil
}

func parseSwitch(name, raw string) (bool, error) {
	switch raw {
	case "", "off":
		return false, nil
	case "on":
		return true, nil
	}
	return false, fmt.Errorf("%s must be on or off", name)
}
