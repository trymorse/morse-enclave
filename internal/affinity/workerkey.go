package affinity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"morse/backend/internal/catalog"
)

type WorkerKey struct{ secret []byte }

func NewWorkerKey(secret [32]byte) WorkerKey { return WorkerKey{secret: secret[:]} }

func (WorkerKey) String() string { return "affinity.WorkerKey(redacted)" }

func (WorkerKey) GoString() string { return "affinity.WorkerKey(redacted)" }

const minPartition = 16

func (k WorkerKey) CacheKey(now time.Time, vendor catalog.EndpointID, model catalog.ModelID, partition []byte, d Digest) string {
	if len(k.secret) == 0 || d.IsZero() || vendor == "" || len(partition) < minPartition {
		return ""
	}
	mac := hmac.New(sha256.New, k.secret)
	mac.Write([]byte("morse/worker-prompt-cache-key/v2\x00" + now.UTC().Format(time.DateOnly) + "\x00"))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(vendor))))
	mac.Write([]byte(vendor))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(model))))
	mac.Write([]byte(model))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(partition))))
	mac.Write(partition)
	mac.Write(d.sum[:])
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
