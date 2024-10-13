package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"time"
)

func Hotp(key []byte, counter uint64, digits int) (int, error) {
	h := hmac.New(sha1.New, key)
	if err := binary.Write(h, binary.BigEndian, counter); err != nil {
		return -1, fmt.Errorf("failed to write counter: %v", err)
	}

	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d), nil
}

func Totp(key []byte, t time.Time, digits int) (int, error) {
	return Hotp(key, uint64(t.UnixNano())/30e9, digits)
}
