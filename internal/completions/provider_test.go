package completions

import (
	"errors"
	"testing"
)

func TestAnEventOfAnUnhandledTypeIsSkippedAndAHandledOneMustDecode(t *testing.T) {
	var read []int
	events := Events{"delta": On(func(e struct {
		N int `json:"n"`
	}) (bool, error) {
		read = append(read, e.N)
		return e.N == 2, nil
	})}
	for _, c := range []struct {
		data string
		done bool
		err  error
	}{
		{`{"type":"delta","n":1}`, false, nil},
		{`{"type":"delta","n":2}`, true, nil},
		{`{"type":"ping","n":"one"}`, false, nil},
		{`{"n":"one"}`, false, nil},
		{`{"type":"delta","n":"one"}`, false, ErrStreamFailed},
		{`{"type":7}`, false, ErrStreamFailed},
		{`not json`, false, ErrStreamFailed},
	} {
		if done, err := events.ByType([]byte(c.data)); done != c.done || !errors.Is(err, c.err) {
			t.Errorf("%s: done %t err %v, want %t %v", c.data, done, err, c.done, c.err)
		}
	}
	if len(read) != 2 || read[0] != 1 || read[1] != 2 {
		t.Errorf("the handler read %v, want only the two well-typed deltas", read)
	}
}
