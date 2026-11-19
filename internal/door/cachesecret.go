package door

import "crypto/rand"

const cacheSecretSize = 32

func (d *Door) CacheSecret() [cacheSecretSize]byte { return d.custody.Load().cacheSecret }

func newCacheSecret() [cacheSecretSize]byte {
	var secret [cacheSecretSize]byte
	rand.Read(secret[:])
	return secret
}

func readableCacheSecret(handed []byte) bool {
	return len(handed) == 0 || len(handed) == cacheSecretSize
}

func adoptedCacheSecret(handed []byte, own [cacheSecretSize]byte) [cacheSecretSize]byte {
	if len(handed) == cacheSecretSize {
		return [cacheSecretSize]byte(handed)
	}
	return own
}
