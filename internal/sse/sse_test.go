package sse_test

import (
	"errors"
	"strings"
	"testing"

	"morse/backend/internal/sse"
)

func collect(stream string, limit int, oversize sse.Oversize, terminal string) ([]string, error) {
	var got []string
	err := sse.Each(strings.NewReader(stream), limit, oversize, func(d []byte) (bool, error) {
		if string(d) == terminal {
			return true, nil
		}
		got = append(got, string(d))
		return false, nil
	})
	return got, err
}

func TestFraming(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream string
		want   []string
		err    error
	}{
		{"the terminal event ends the stream", "data: a\n\ndata: [DONE]\n\ndata: b\n\n", []string{"a"}, nil},
		{"crlf and no space", "data:a\r\n\r\ndata:[DONE]\r\n\r\n", []string{"a"}, nil},
		{"multi-line data joins with newline", "data: a\ndata: b\n\ndata: [DONE]\n\n", []string{"a\nb"}, nil},
		{"comments and other fields ignored", ": ping\nevent: x\nid: 1\ndata: a\n\n\n\ndata: [DONE]\n\n", []string{"a"}, nil},
		{"terminal event without trailing blank line", "data: a\n\ndata: [DONE]", []string{"a"}, nil},
		{"eof before the terminal event", "data: a\n\n", []string{"a"}, sse.ErrTruncated},
		{"partial event at eof", "data: a\n\ndata: b", []string{"a", "b"}, sse.ErrTruncated},
		{"empty stream", "", nil, sse.ErrTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := collect(tc.stream, 1<<10, sse.Refuse, "[DONE]")
			if !errors.Is(err, tc.err) || strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("got %q err %v, want %q err %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestAnEventOverTheLimitFailsBeforeItIsDelivered(t *testing.T) {
	for name, stream := range map[string]string{
		"one long line":         "data: " + strings.Repeat("x", 65) + "\n\ndata: [DONE]\n\n",
		"many lines in a event": strings.Repeat("data: "+strings.Repeat("x", 20)+"\n", 4) + "\ndata: [DONE]\n\n",
	} {
		got, err := collect("data: a\n\n"+stream, 64, sse.Refuse, "[DONE]")
		if !errors.Is(err, sse.ErrTooLarge) || strings.Join(got, "|") != "a" {
			t.Errorf("%s: got %q err %v", name, got, err)
		}
	}
}

func TestClipDeliversAnOversizedEventCutJustPastTheLimit(t *testing.T) {
	got, err := collect("data: "+strings.Repeat("x", 3<<16)+"\n\ndata: b\n\ndata: [DONE]\n\n", 64, sse.Clip, "[DONE]")
	if err != nil || len(got) != 2 || got[0] != strings.Repeat("x", 65) || got[1] != "b" {
		t.Errorf("err %v, got %d events, first %d bytes", err, len(got), len(got[0]))
	}
}

func TestAnEventLargerThanTheReadBufferIsDeliveredWhole(t *testing.T) {
	big := strings.Repeat("y", 200<<10)
	got, err := collect("data: "+big+"\n\ndata: [DONE]\n\n", 1<<20, sse.Refuse, "[DONE]")
	if err != nil || len(got) != 1 || got[0] != big {
		t.Errorf("err %v events %d", err, len(got))
	}
}

func TestACallbackErrorStopsTheStream(t *testing.T) {
	stop := errors.New("stop")
	calls := 0
	err := sse.Each(strings.NewReader("data: a\n\ndata: b\n\n"), 64, sse.Refuse, func([]byte) (bool, error) {
		calls++
		return false, stop
	})
	if !errors.Is(err, stop) || calls != 1 {
		t.Errorf("err %v after %d calls", err, calls)
	}
}

func TestFramesHandOverEveryByteAndNameWhatAClientWouldReadDifferently(t *testing.T) {
	stream := ": ping\n\ndata: a\n: inside\ndata: b\n\nevent: x\ndata: c\n\ndata: d\rdata: e\n\nDATA: f\n\ndata:\n\ndata: [DONE]"
	var got []sse.Frame
	err := sse.Frames(strings.NewReader(stream), 1<<10, sse.Refuse, func(f sse.Frame) error {
		got = append(got, sse.Frame{Raw: []byte(string(f.Raw)), Data: cloneData(f.Data), Opaque: f.Opaque})
		return nil
	})
	want := []sse.Frame{
		{Raw: []byte(": ping\n")},
		{Raw: []byte("\n")},
		{Raw: []byte("data: a\n: inside\ndata: b\n\n"), Data: []byte("a\nb")},
		{Raw: []byte("event: x\n"), Opaque: true},
		{Raw: []byte("data: c\n\n"), Data: []byte("c")},
		{Raw: []byte("data: d\rdata: e\n\n"), Data: []byte("d\rdata: e"), Opaque: true},
		{Raw: []byte("DATA: f\n"), Opaque: true},
		{Raw: []byte("\n")},
		{Raw: []byte("data:\n\n"), Data: []byte{}},
		{Raw: []byte("data: [DONE]"), Data: []byte("[DONE]")},
	}
	if err != nil || len(got) != len(want) {
		t.Fatalf("err %v, %d frames, want %d", err, len(got), len(want))
	}
	var whole string
	for i := range want {
		whole += string(got[i].Raw)
		if string(got[i].Raw) != string(want[i].Raw) || (got[i].Data == nil) != (want[i].Data == nil) || string(got[i].Data) != string(want[i].Data) || got[i].Opaque != want[i].Opaque {
			t.Errorf("frame %d: raw %q data %q opaque %t, want raw %q data %q opaque %t", i, got[i].Raw, got[i].Data, got[i].Opaque, want[i].Raw, want[i].Data, want[i].Opaque)
		}
	}
	if whole != stream {
		t.Errorf("the frames add up to %q, not the stream", whole)
	}
}

func cloneData(d []byte) []byte {
	if d == nil {
		return nil
	}
	return append([]byte{}, d...)
}

func TestEachKeepsAnEmptyEventAndABareCRInsideAData(t *testing.T) {
	got, err := collect("data:\n\ndata: a\rb\n\ndata: [DONE]\n\n", 64, sse.Refuse, "[DONE]")
	if err != nil || len(got) != 2 || got[0] != "" || got[1] != "a\rb" {
		t.Errorf("got %q err %v, want an empty event and a\\rb", got, err)
	}
}

func TestEachBoundsAnEventByItsDataAloneNotItsPrefixesOrComments(t *testing.T) {
	full := strings.Repeat("x", 64)
	got, err := collect("data: "+full+"\n\ndata: [DONE]\n\n", 64, sse.Refuse, "[DONE]")
	if err != nil || len(got) != 1 || got[0] != full {
		t.Fatalf("an event of exactly the limit: %q, %v", got, err)
	}
	got, err = collect("data: "+full[:30]+"\n: keep\n: keep\ndata: "+full[:33]+"\n\ndata: [DONE]\n\n", 64, sse.Refuse, "[DONE]")
	if err != nil || len(got) != 1 || len(got[0]) != 64 {
		t.Fatalf("an event of the limit with comments inside: %q, %v", got, err)
	}
	if _, err := collect("data: "+full+"x\n\n", 64, sse.Refuse, "[DONE]"); !errors.Is(err, sse.ErrTooLarge) {
		t.Fatalf("an event one byte over: %v", err)
	}
}
