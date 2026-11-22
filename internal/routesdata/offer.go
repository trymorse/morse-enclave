package routesdata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"morse/backend/internal/strictjson"
	"morse/backend/internal/upstream"
)

const OfferURL = "http://10.0.0.1:8099/routes"

const maxOfferBody = (2*MaxStatement+MaxFile)*4/3 + 4096

var (
	ErrNoOffer  = errors.New("routesdata: the host offers no routes file")
	ErrNotOffer = errors.New("routesdata: the host's answer is not a statement, a bundle and a routes file")
)

func Fetch(ctx context.Context, client *http.Client, url string) (Offer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Offer{}, err
	}
	resp, err := upstream.Do(client, req)
	if err != nil {
		return Offer{}, fmt.Errorf("routesdata: the host's offer could not be read: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Offer{}, ErrNoOffer
	default:
		return Offer{}, fmt.Errorf("routesdata: the host answered its offer with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOfferBody+1))
	if err != nil {
		return Offer{}, fmt.Errorf("routesdata: the host's offer could not be read: %w", err)
	}
	if len(body) > maxOfferBody {
		return Offer{}, fmt.Errorf("%w: the host's offer is over %d bytes", ErrSize, maxOfferBody)
	}
	return parseOffer(body)
}

func parseOffer(body []byte) (Offer, error) {
	fields, err := strictjson.Object(bytes.NewReader(body), "statement", "bundle", "file")
	if err != nil || len(fields) != 3 {
		return Offer{}, ErrNotOffer
	}
	var o Offer
	for name, into := range map[string]*[]byte{"statement": &o.Statement, "bundle": &o.Bundle, "file": &o.File} {
		if json.Unmarshal(fields[name], into) != nil || len(*into) == 0 {
			return Offer{}, ErrNotOffer
		}
	}
	return o, nil
}
