package clip

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"morse/backend/internal/media"
)

type bucket struct {
	*httptest.Server
	mu      sync.Mutex
	objects map[string][]byte
	puts    int
	status  int
}

func newBucket(t *testing.T) *bucket {
	b := &bucket{objects: map[string][]byte{}, status: http.StatusOK}
	b.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.puts++
		if r.Method != http.MethodPut || err != nil || int64(len(body)) != r.ContentLength {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if b.status != http.StatusOK {
			w.WriteHeader(b.status)
			return
		}
		b.objects[r.URL.Path] = body
		w.Header().Set("ETag", `"sealed"`)
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *bucket) object(path string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.objects[path]
	return o, ok
}

type door struct {
	*httptest.Server
	rc       *Receiver
	bucket   *bucket
	origin   Origin
	key      *TicketKey
	pending  atomic.Bool
	outcomes chan Outcome
}

func newTicketKey(t *testing.T, epoch byte) *TicketKey {
	t.Helper()
	var fleet [KeySize]byte
	rand.Read(fleet[:])
	k, err := NewTicketKey(fleet, [EpochSize]byte{epoch})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newDoor(t *testing.T) *door {
	b := newBucket(t)
	store, err := ParseStore("STORE", b.URL+"/clips")
	if err != nil {
		t.Fatal(err)
	}
	d := &door{bucket: b, key: newTicketKey(t, 1), outcomes: make(chan Outcome, 16)}
	d.rc = NewReceiver(store, func() (*TicketKey, bool) { return d.key, !d.pending.Load() }, b.Client().Transport)
	rc := d.rc
	rc.Observe = func(o Outcome) { d.outcomes <- o }
	mux := http.NewServeMux()
	mux.Handle(UploadPattern, rc)
	d.Server = httptest.NewTLSServer(mux)
	t.Cleanup(d.Close)
	if d.origin, err = ParseOrigin("ORIGIN", d.URL); err != nil {
		t.Fatal(err)
	}
	return d
}

func (d *door) ticket(clip string) Ticket {
	return Ticket{Key: NewKey(), Clip: clip, Store: d.bucket.URL + "/clips/v/" + clip + "?X-Amz-Signature=s", Deadline: time.Now().Add(time.Minute)}
}

func (d *door) url(tk Ticket) string { return tk.URL(d.origin, d.key) }

func (d *door) sealedURL(version byte, epoch [EpochSize]byte, k *TicketKey, plain []byte) string {
	head := append([]byte{version}, epoch[:]...)
	nonce := make([]byte, nonceSize)
	rand.Read(nonce)
	return d.URL + UploadPath + base64.RawURLEncoding.EncodeToString(k.aead.Seal(append(head, nonce...), nonce, plain, head))
}

func (d *door) put(t *testing.T, url string, body io.Reader, size int64) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "video/mp4")
	resp, err := d.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (d *door) outcome(t *testing.T) Outcome {
	t.Helper()
	return <-d.outcomes
}

func TestAVendorsUploadReachesTheBucketOnlySealed(t *testing.T) {
	d := newDoor(t)
	clip := make([]byte, 3*SegmentSize+11)
	rand.Read(clip)
	tk := d.ticket("video_1")
	resp := d.put(t, d.url(tk), bytes.NewReader(clip), int64(len(clip)))
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"sealed"` {
		t.Fatalf("the upload got %d with ETag %q, want 200 and the store's ETag", resp.StatusCode, resp.Header.Get("ETag"))
	}
	if o := d.outcome(t); o != Stored {
		t.Errorf("outcome %s, want %s", o, Stored)
	}
	sealed, ok := d.bucket.object("/clips/v/video_1")
	if !ok {
		t.Fatal("the bucket holds nothing at the ticket's key")
	}
	if int64(len(sealed)) != SealedSize(int64(len(clip))) || bytes.Contains(sealed, clip[:64]) {
		t.Errorf("the bucket holds %d bytes, want %d of ciphertext with no run of the clip", len(sealed), SealedSize(int64(len(clip))))
	}
	got, err := openAll(tk.Key, "video_1", sealed)
	if err != nil || !bytes.Equal(got, clip) {
		t.Errorf("the stored clip opened to %d bytes, %v", len(got), err)
	}
}

func TestTheDoorRefusesAnUploadItCannotSealIntoTheStore(t *testing.T) {
	d := newDoor(t)
	good := d.ticket("video_1")
	elsewhere := good
	elsewhere.Store = "https://attacker.example/clips/v/video_1"
	outside := good
	outside.Store = d.bucket.URL + "/other/v/video_1"
	climbing := good
	climbing.Store = d.bucket.URL + "/clips/../other/v/video_1"
	plain := good
	plain.Store = strings.Replace(d.bucket.URL, "https://", "http://", 1) + "/clips/v/video_1"
	lapsed := good
	lapsed.Deadline = time.Now().Add(-time.Second)
	fields, _ := json.Marshal(map[string]any{"k": good.Key[:], "c": "video_1", "s": good.Store, "d": good.Deadline.Unix()})
	extraField, _ := json.Marshal(map[string]any{"k": good.Key[:], "c": "video_1", "s": good.Store, "d": good.Deadline.Unix(), "x": 1})
	shortKey, _ := json.Marshal(map[string]any{"k": good.Key[:16], "c": "video_1", "s": good.Store, "d": good.Deadline.Unix()})
	unsigned, _ := json.Marshal(map[string]any{"v": 1, "k": good.Key[:], "c": "video_1", "s": good.Store, "d": good.Deadline.Unix()})
	raw := func(b []byte) string { return d.URL + UploadPath + base64.RawURLEncoding.EncodeToString(b) }
	otherFleet := newTicketKey(t, 1)
	tampered, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(d.url(good), d.URL+UploadPath))
	tampered[len(tampered)/2] ^= 1
	body := []byte("frames")
	for name, c := range map[string]struct {
		url    string
		size   int64
		status int
	}{
		"another host":                {d.url(elsewhere), 6, http.StatusNotFound},
		"outside the store's path":    {d.url(outside), 6, http.StatusNotFound},
		"climbing out of the store":   {d.url(climbing), 6, http.StatusNotFound},
		"plain http":                  {d.url(plain), 6, http.StatusNotFound},
		"not a ticket":                {d.URL + UploadPath + "frames", 6, http.StatusNotFound},
		"a ticket in the clear":       {raw(unsigned), 6, http.StatusNotFound},
		"another fleet's key":         {d.sealedURL(ticketVersion, d.key.epoch, otherFleet, fields), 6, http.StatusNotFound},
		"another epoch":               {d.sealedURL(ticketVersion, [EpochSize]byte{2}, d.key, fields), 6, http.StatusNotFound},
		"another version":             {d.sealedURL(2, d.key.epoch, d.key, fields), 6, http.StatusNotFound},
		"a ticket altered in transit": {raw(tampered), 6, http.StatusNotFound},
		"an unknown field":            {d.sealedURL(ticketVersion, d.key.epoch, d.key, extraField), 6, http.StatusNotFound},
		"a short key":                 {d.sealedURL(ticketVersion, d.key.epoch, d.key, shortKey), 6, http.StatusNotFound},
		"a ticket too long":           {d.URL + UploadPath + strings.Repeat("A", maxTicket+1), 6, http.StatusNotFound},
		"lapsed":                      {d.url(lapsed), 6, http.StatusGone},
		"no Content-Length":           {d.url(good), -1, http.StatusLengthRequired},
		"larger than the door takes":  {d.url(good), MaxClipBytes + 1, http.StatusRequestEntityTooLarge},
	} {
		var r io.Reader = bytes.NewReader(body)
		if c.size > int64(len(body)) {
			r = io.LimitReader(rand.Reader, c.size)
		}
		resp := d.put(t, c.url, r, c.size)
		if resp.StatusCode != c.status {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, c.status)
		}
		if o := d.outcome(t); o != Refused {
			t.Errorf("%s: outcome %s, want %s", name, o, Refused)
		}
	}
	if d.bucket.puts != 0 {
		t.Errorf("the bucket saw %d PUTs, want none", d.bucket.puts)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		req, _ := http.NewRequest(method, d.url(good), nil)
		resp, err := d.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d, want 405", method, resp.StatusCode)
		}
	}
}

func TestAStoreThatFailsFailsTheUpload(t *testing.T) {
	d := newDoor(t)
	d.bucket.status = http.StatusForbidden
	resp := d.put(t, d.url(d.ticket("video_1")), strings.NewReader("frames"), 6)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("%d, want 502 so the vendor does not count the clip stored", resp.StatusCode)
	}
	if o := d.outcome(t); o != StoreFailed {
		t.Errorf("outcome %s, want %s", o, StoreFailed)
	}
	d.bucket.Close()
	resp = d.put(t, d.url(d.ticket("video_2")), strings.NewReader("frames"), 6)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("an unreachable store: %d, want 502", resp.StatusCode)
	}
}

func TestAnUploadThatEndsEarlyStoresNothing(t *testing.T) {
	d := newDoor(t)
	tk := d.ticket("video_1")
	req, _ := http.NewRequest(http.MethodPut, d.url(tk), io.MultiReader(strings.NewReader(strings.Repeat("f", SegmentSize+5)), failing{}))
	req.ContentLength = 2 * SegmentSize
	if resp, err := d.Client().Do(req); err == nil {
		resp.Body.Close()
	}
	if o := d.outcome(t); o != UploadBroken {
		t.Errorf("outcome %s, want %s", o, UploadBroken)
	}
	if _, ok := d.bucket.object("/clips/v/video_1"); ok {
		t.Error("the bucket stored a clip whose upload broke off")
	}
}

func TestATicketDueAsLateAsTheRelaysVideoJobIsStored(t *testing.T) {
	d := newDoor(t)
	tk := d.ticket("video_1")
	tk.Deadline = time.Now().Add(media.VideoJobLifetime)
	if resp := d.put(t, d.url(tk), strings.NewReader("frames"), 6); resp.StatusCode != http.StatusOK {
		t.Errorf("a ticket due when its job is: %d, want 200", resp.StatusCode)
	}
	if o := d.outcome(t); o != Stored {
		t.Errorf("outcome %s, want %s", o, Stored)
	}
	if _, ok := d.bucket.object("/clips/v/video_1"); !ok {
		t.Error("the bucket holds nothing at the ticket's key")
	}
}

func TestAnUploadAdmittedBeforeItsDeadlineIsStoredAfterIt(t *testing.T) {
	d := newDoor(t)
	d.rc.Now = func() time.Time { return time.Now().Add(-time.Minute) }
	tk := d.ticket("video_1")
	tk.Deadline = time.Now().Add(-time.Second)
	if resp := d.put(t, d.url(tk), strings.NewReader("frames"), 6); resp.StatusCode != http.StatusOK {
		t.Errorf("an upload admitted before its deadline and stored after it: %d, want 200", resp.StatusCode)
	}
	if o := d.outcome(t); o != Stored {
		t.Errorf("outcome %s, want %s", o, Stored)
	}
	if _, ok := d.bucket.object("/clips/v/video_1"); !ok {
		t.Error("the bucket holds nothing at the ticket's key")
	}
}

func TestAForgedTicketIsRefusedWithoutWaitingForASlot(t *testing.T) {
	d := newDoor(t)
	for range ReceiveSlots {
		d.rc.slots <- struct{}{}
	}
	forged := d.ticket("video_1")
	resp := d.put(t, forged.URL(d.origin, newTicketKey(t, 1)), strings.NewReader("frames"), 6)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a forged ticket with every slot held: %d, want 404 before any slot", resp.StatusCode)
	}
	if o := d.outcome(t); o != Refused {
		t.Errorf("outcome %s, want %s", o, Refused)
	}
	if len(d.rc.slots) != ReceiveSlots || d.bucket.puts != 0 {
		t.Errorf("%d slots held and %d PUTs, want the forged ticket to change neither", len(d.rc.slots), d.bucket.puts)
	}
}

func TestADoorWithNoFleetKeyYetTakesNoUpload(t *testing.T) {
	d := newDoor(t)
	tk := d.ticket("video_1")
	d.pending.Store(true)
	resp := d.put(t, d.url(tk), strings.NewReader("frames"), 6)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Errorf("%d with Retry-After %q, want 503 with one while the fleet key is pending", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if o := d.outcome(t); o != Refused {
		t.Errorf("outcome %s, want %s", o, Refused)
	}
	d.pending.Store(false)
	if resp := d.put(t, d.url(tk), strings.NewReader("frames"), 6); resp.StatusCode != http.StatusOK {
		t.Errorf("the same ticket once the key settled: %d, want 200", resp.StatusCode)
	}
	if o := d.outcome(t); o != Stored {
		t.Errorf("outcome %s, want %s", o, Stored)
	}
}

func TestTheDoorReceivesOnlyAsManyClipsAtOnceAsItHasSlots(t *testing.T) {
	d := newDoor(t)
	for range ReceiveSlots {
		d.rc.slots <- struct{}{}
	}
	resp := d.put(t, d.url(d.ticket("video_1")), strings.NewReader("frames"), 6)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Errorf("%d with Retry-After %q, want 503 with one", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if o := d.outcome(t); o != Busy {
		t.Errorf("outcome %s, want %s", o, Busy)
	}
}

func TestATicketCarriesItsFieldsAndAnOriginOrStoreTakesOnlyHTTPS(t *testing.T) {
	origin, err := ParseOrigin("O", "https://inference.trymorse.ai/")
	if err != nil {
		t.Fatal(err)
	}
	tk := Ticket{Key: NewKey(), Clip: "video_x", Store: "https://acct.r2.cloudflarestorage.com/bucket/v/x?X-Amz-Signature=s", Deadline: time.Unix(1795255290, 0)}
	key := newTicketKey(t, 7)
	url := tk.URL(origin, key)
	enc, ok := strings.CutPrefix(url, "https://inference.trymorse.ai"+UploadPath)
	if !ok {
		t.Fatalf("URL %s is not on the origin's upload path", url)
	}
	back, err := ParseTicket(key, enc)
	if err != nil || back != tk {
		t.Errorf("ParseTicket = %+v, %v; want %+v", back, err, tk)
	}
	wire, _ := base64.RawURLEncoding.DecodeString(enc)
	for name, clear := range map[string][]byte{"the clip's key": tk.Key[:], "the store": []byte("r2.cloudflarestorage.com"), "the signature": []byte("X-Amz-Signature"), "the clip": []byte("video_x")} {
		if bytes.Contains(wire, clear) {
			t.Errorf("the ticket carries %s in the clear", name)
		}
	}
	if again := tk.URL(origin, key); again == url {
		t.Error("two tickets for one clip are the same bytes, want a fresh nonce each")
	}
	if _, err := ParseTicket(newTicketKey(t, 8), enc); !errors.Is(err, ErrTicketEpoch) {
		t.Errorf("a ticket of another epoch: %v, want ErrTicketEpoch", err)
	}
	if _, err := ParseTicket(newTicketKey(t, 7), enc); !errors.Is(err, ErrTicket) {
		t.Errorf("a ticket under another fleet key of the same epoch: %v, want ErrTicket", err)
	}
	var fleet [KeySize]byte
	rand.Read(fleet[:])
	one, _ := NewTicketKey(fleet, [EpochSize]byte{9})
	other, _ := NewTicketKey(fleet, [EpochSize]byte{9})
	if back, err := ParseTicket(other, strings.TrimPrefix(tk.URL(origin, one), "https://inference.trymorse.ai"+UploadPath)); err != nil || back != tk {
		t.Errorf("a ticket one instance sealed, opened on another holding the same fleet key: %+v, %v", back, err)
	}
	for _, raw := range []string{"http://inference.trymorse.ai", "https://inference.trymorse.ai/v1", "https://u@inference.trymorse.ai", "https://inference.trymorse.ai?x=1", "inference.trymorse.ai"} {
		if _, err := ParseOrigin("O", raw); err == nil {
			t.Errorf("origin %q parsed", raw)
		}
	}
	for _, raw := range []string{"http://acct.r2.cloudflarestorage.com/bucket", "https://acct.r2.cloudflarestorage.com/bucket?x=1", "https://u:p@acct.r2.cloudflarestorage.com/bucket", "acct/bucket"} {
		if _, err := ParseStore("S", raw); err == nil {
			t.Errorf("store %q parsed", raw)
		}
	}
	store, err := ParseStore("S", "https://acct.r2.cloudflarestorage.com/bucket/")
	if err != nil {
		t.Fatal(err)
	}
	for dest, holds := range map[string]bool{
		tk.Store: true,
		"https://acct.r2.cloudflarestorage.com/bucket":           false,
		"https://acct.r2.cloudflarestorage.com/bucket/":          false,
		"https://acct.r2.cloudflarestorage.com/bucketeer/v/x":    false,
		"https://acct.r2.cloudflarestorage.com/bucket/./v/x":     false,
		"https://acct.r2.cloudflarestorage.com/bucket/%2e%2e/x":  false,
		"https://acct.r2.cloudflarestorage.com:8443/bucket/v/x":  false,
		"https://evil.example/bucket/v/x":                        false,
		"https://acct.r2.cloudflarestorage.com/bucket/v/x#frag":  false,
		"https://me@acct.r2.cloudflarestorage.com/bucket/v/x":    false,
		"https://acct.r2.cloudflarestorage.com.evil/bucket/v/x":  false,
		"https://acct.r2.cloudflarestorage.com/bucket/v/x?a=b&c": true,
	} {
		if store.Holds(dest) != holds {
			t.Errorf("Holds(%q) = %t, want %t", dest, !holds, holds)
		}
	}
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
