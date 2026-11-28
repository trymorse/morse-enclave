package upstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

var ErrDispatchLimit = errors.New("upstream: the validation dispatch limit refused this chat")

type DispatchLimit struct {
	Chats                   int   `json:"chats"`
	Micros                  int64 `json:"micros"`
	BodyBytes               int   `json:"body_bytes"`
	MaxTokens               int   `json:"max_tokens"`
	PromptMicrosPerMtok     int64 `json:"prompt_micros_per_mtok"`
	CompletionMicrosPerMtok int64 `json:"completion_micros_per_mtok"`
	used                    string
}

var dispatchLimit atomic.Pointer[DispatchLimit]

func LimitDispatches(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var l DispatchLimit
	if err := json.Unmarshal(raw, &l); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	// why: reserve multiplies body bytes and tokens by their prices in int64, so each input is held to a range whose
	// products stay below 2^63 (at most 2^24 bytes or 2^20 tokens times under 10^9 micros per million tokens).
	if !within(l.Chats, 1_000_000) || !within(l.Micros, 1_000_000_000_000_000) || !within(l.BodyBytes, 1<<24) || !within(l.MaxTokens, 1<<20) ||
		!within(l.PromptMicrosPerMtok, 999_999_999) || !within(l.CompletionMicrosPerMtok, 999_999_999) {
		return fmt.Errorf("%s names chats, micros, body_bytes, max_tokens or prices outside 1 to their limits", path)
	}
	l.used = path + ".used"
	if _, _, err := readUsed(l.used); err != nil {
		return err
	}
	dispatchLimit.Store(&l)
	return nil
}

func readUsed(path string) (int, int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	chats, micros, ok := strings.Cut(strings.TrimSpace(string(raw)), " ")
	n, err1 := strconv.Atoi(chats)
	m, err2 := strconv.ParseInt(micros, 10, 64)
	if !ok || err1 != nil || err2 != nil || n < 0 || m < 0 {
		return 0, 0, fmt.Errorf("%s holds no count of chats and micros", path)
	}
	return n, m, nil
}

// why: the final body's bytes are priced as prompt tokens and its output limit as completion tokens, which bounds a
// vendor's bill only if it adds no prompt tokens and bills no output past the limit; Phala's and NEAR's terms state
// neither (verify/features/e2ee.md), so the count bounds what is sent, not what is charged.
func (l *DispatchLimit) reserve(req *http.Request) error {
	if req.GetBody == nil {
		return fmt.Errorf("%w: a body that cannot be read twice", ErrDispatchLimit)
	}
	copied, err := req.GetBody()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDispatchLimit, err)
	}
	defer copied.Close()
	var body bytes.Buffer
	if _, err := io.Copy(&body, io.LimitReader(copied, int64(l.BodyBytes)+1)); err != nil {
		return fmt.Errorf("%w: %w", ErrDispatchLimit, err)
	}
	if body.Len() > l.BodyBytes {
		return fmt.Errorf("%w: a body over %d bytes", ErrDispatchLimit, l.BodyBytes)
	}
	var asked struct {
		MaxTokens           int `json:"max_tokens"`
		MaxCompletionTokens int `json:"max_completion_tokens"`
	}
	if err := json.Unmarshal(body.Bytes(), &asked); err != nil {
		return fmt.Errorf("%w: a body that is not JSON", ErrDispatchLimit)
	}
	tokens := max(asked.MaxTokens, asked.MaxCompletionTokens)
	if tokens <= 0 || tokens > l.MaxTokens {
		return fmt.Errorf("%w: max_tokens %d, not 1 to %d", ErrDispatchLimit, tokens, l.MaxTokens)
	}
	cost := ceilMicros(int64(body.Len()), l.PromptMicrosPerMtok) + ceilMicros(int64(tokens), l.CompletionMicrosPerMtok)
	f, err := os.OpenFile(l.used, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDispatchLimit, err)
	}
	defer f.Close()
	// why: replicas in separate processes share one count, so read, check and write happen under one lock on the file.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("%w: %w", ErrDispatchLimit, err)
	}
	chats, micros, err := readUsed(l.used)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDispatchLimit, err)
	}
	// why: compared with what is left rather than added to the count, so a count already near or past the limit
	// refuses instead of wrapping past it.
	if chats >= l.Chats || cost > l.Micros-micros {
		return fmt.Errorf("%w: %d of %d chats and %d of %d micros spent, this one %d", ErrDispatchLimit, chats, l.Chats, micros, l.Micros, cost)
	}
	if _, err := f.WriteAt([]byte(fmt.Sprintf("%d %d\n", chats+1, micros+cost)), 0); err != nil {
		return fmt.Errorf("%w: %w", ErrDispatchLimit, err)
	}
	return f.Sync()
}

func ceilMicros(tokens, microsPerMtok int64) int64 {
	return (tokens*microsPerMtok + 999_999) / 1_000_000
}

func within[T int | int64](n, most T) bool { return n >= 1 && n <= most }
