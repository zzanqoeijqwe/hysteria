package obfs

import (
	"crypto/sha256"
	"math/rand"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
)

const (
	xpSaltLen     = 16
	udpBufferSize = 4096
)

// XPlusObfuscator obfuscates payload using one-time keys generated from hashing a pre-shared key and random salt.
// Packet format: [salt][obfuscated payload]
type XPlusObfuscator struct {
	key      []byte
	randSrc  *rand.Rand
	randLk   sync.Mutex
	bufPool  sync.Pool
	saltPool sync.Pool
}

func NewXPlusObfuscator(key []byte) quic.Obfuscator {
	return &XPlusObfuscator{
		key:      key,
		randSrc:  rand.New(rand.NewSource(time.Now().UnixNano())),
		bufPool:  sync.Pool{New: func() interface{} { return make([]byte, udpBufferSize) }},
		saltPool: sync.Pool{New: func() interface{} { return make([]byte, xpSaltLen) }},
	}
}

func (x *XPlusObfuscator) Obfuscate(data []byte, scat bool) ([][]byte, func()) {
	if scat {
		salt := x.saltPool.Get().([]byte)
		x.randLk.Lock()
		_, _ = x.randSrc.Read(salt)
		x.randLk.Unlock()
		key := sha256.Sum256(append(x.key, salt...))
		buf := x.bufPool.Get().([]byte)
		for i, c := range data {
			buf[i] = c ^ key[i%sha256.Size]
		}
		payload := buf[:len(data)]
		return [][]byte{salt, payload}, func() {
			x.saltPool.Put(salt)
			x.bufPool.Put(buf)
		}
	} else {
		buf := x.bufPool.Get().([]byte)
		x.randLk.Lock()
		_, _ = x.randSrc.Read(buf[:xpSaltLen])
		x.randLk.Unlock()
		key := sha256.Sum256(append(x.key, buf[:xpSaltLen]...))
		for i, c := range data {
			buf[i+xpSaltLen] = c ^ key[i%sha256.Size]
		}
		payload := buf[:xpSaltLen+len(data)]
		return [][]byte{payload}, func() {
			x.bufPool.Put(buf)
		}
	}
}

func (x *XPlusObfuscator) Deobfuscate(data []byte) int {
	if len(data) <= xpSaltLen {
		return 0
	}
	key := sha256.Sum256(append(x.key, data[:xpSaltLen]...))
	for i, c := range data[xpSaltLen:] {
		data[i] = c ^ key[i%sha256.Size]
	}
	return len(data) - xpSaltLen
}
