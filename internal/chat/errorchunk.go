package chat

import (
	"encoding/json"

	"morse/backend/internal/enum"
)

type ErrorChunk struct{ Code ErrorCode }

func (e ErrorChunk) Error() string {
	return "chat: the upstream stream carried an error chunk, code " + e.Code.String()
}

type ErrorCode uint8

const (
	OtherErrorCode ErrorCode = iota
	APIError
	BadGateway
	ContentFilter
	ContextLengthExceeded
	GatewayTimeout
	InsufficientQuota
	InternalError
	InternalServerError
	InvalidRequestError
	OverloadedError
	RateLimitError
	RateLimitExceeded
	ServerError
	ServerIsOverloaded
	ServiceUnavailable
	Timeout
	Status400
	Status401
	Status402
	Status403
	Status404
	Status408
	Status413
	Status422
	Status429
	Status500
	Status502
	Status503
	Status504
)

var errorCodeNames = enum.Names[ErrorCode]{
	OtherErrorCode:        "other",
	APIError:              "api_error",
	BadGateway:            "bad_gateway",
	ContentFilter:         "content_filter",
	ContextLengthExceeded: "context_length_exceeded",
	GatewayTimeout:        "gateway_timeout",
	InsufficientQuota:     "insufficient_quota",
	InternalError:         "internal_error",
	InternalServerError:   "internal_server_error",
	InvalidRequestError:   "invalid_request_error",
	OverloadedError:       "overloaded_error",
	RateLimitError:        "rate_limit_error",
	RateLimitExceeded:     "rate_limit_exceeded",
	ServerError:           "server_error",
	ServerIsOverloaded:    "server_is_overloaded",
	ServiceUnavailable:    "service_unavailable",
	Timeout:               "timeout",
	Status400:             "400",
	Status401:             "401",
	Status402:             "402",
	Status403:             "403",
	Status404:             "404",
	Status408:             "408",
	Status413:             "413",
	Status422:             "422",
	Status429:             "429",
	Status500:             "500",
	Status502:             "502",
	Status503:             "503",
	Status504:             "504",
}

func (c ErrorCode) String() string { return errorCodeNames.String(c) }

func ErrorChunkCoded(code string) ErrorChunk {
	known, _ := errorCodeNames.Parse(code)
	return ErrorChunk{Code: known}
}

func ErrorChunkOf(object json.RawMessage) ErrorChunk {
	var e struct {
		Code json.RawMessage `json:"code"`
	}
	if json.Unmarshal(object, &e) != nil {
		return ErrorChunk{}
	}
	var name string
	if json.Unmarshal(e.Code, &name) == nil {
		return ErrorChunkCoded(name)
	}
	var status int
	if json.Unmarshal(e.Code, &status) == nil {
		return ErrorChunkCoded(string(e.Code))
	}
	return ErrorChunk{}
}
