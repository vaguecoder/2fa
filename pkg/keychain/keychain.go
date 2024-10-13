package keychain

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/vaguecoder/2fa/pkg/otp"

	"github.com/atotto/clipboard"
)

const CounterLen = 20

type key struct {
	raw    []byte
	digits int
	offset int // offset of counter
}

type keychain struct {
	file *os.File
	data []byte
	keys map[string]key
}

type Keychain interface {
	List()
	Add(name, secret string, isHOTP bool, keySize int) error
	Show(name string, copyToClipboard bool) error
	ShowAll() error
	SetKey(name string, key key)

	getCode(name string) (string, error)
}

func NewKeychain(file *os.File, keys map[string]key, data []byte) Keychain {
	return &keychain{
		file: file,
		data: data,
		keys: keys,
	}
}

func (k *keychain) List() {
	var names []string
	for name := range k.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func (k *keychain) Add(name, secret string, isHOTP bool, keySize int) error {
	secret = strings.Map(noSpace, secret)
	secret += strings.Repeat("=", -len(secret)&7) // pad to 8 bytes
	if _, err := DecodeKey(secret); err != nil {
		return fmt.Errorf("invalid key %q: %v", name, err)
	}

	line := fmt.Sprintf("%s %d %s", name, keySize, secret)
	if isHOTP {
		line += " " + strings.Repeat("0", 20)
	}
	line += "\n"

	if _, err := k.file.Write([]byte(line)); err != nil {
		return fmt.Errorf("failed to add key: %v", err)
	}

	return nil
}

func (k *keychain) Show(name string, copyToClipboard bool) error {
	code, err := k.getCode(name)
	if err != nil {
		return fmt.Errorf("failed to code keychain %q: %v", name, err)
	}

	if copyToClipboard {
		if err := clipboard.WriteAll(code); err != nil {
			return fmt.Errorf("failed to write to clipboard: %v", err)
		}
	}
	fmt.Printf("%s\n", code)

	return nil
}

func (k *keychain) ShowAll() error {
	var names []string
	max := 0
	for name, k := range k.keys {
		names = append(names, name)
		if max < k.digits {
			max = k.digits
		}
	}

	sort.Strings(names)
	for _, name := range names {
		key := k.keys[name]
		code := strings.Repeat("-", key.digits)

		if key.offset == 0 {
			var err error
			code, err = k.getCode(name)
			if err != nil {
				return fmt.Errorf("failed to code keychain: %v", err)
			}
		}

		fmt.Printf("%-*s\t%s\n", max, code, name)
	}

	return nil
}

func (k *keychain) SetKey(name string, key key) {
	k.keys[name] = key
}

func (k *keychain) getCode(name string) (string, error) {
	key, ok := k.keys[name]
	if !ok {
		return "", fmt.Errorf("key %q not found", name)
	}

	var (
		code int
		err  error
	)

	if key.offset != 0 {
		num, err := strconv.ParseUint(string(k.data[key.offset:key.offset+CounterLen]), 10, 64)
		if err != nil {
			return "", fmt.Errorf("malformed key counter for %q (%q)", name, k.data[key.offset:key.offset+CounterLen])
		}
		num++

		code, err = otp.Hotp(key.raw, num, key.digits)
		if err != nil {
			return "", fmt.Errorf("failed to get HOTP: %v", err)
		}

		if _, err := k.file.WriteAt([]byte(fmt.Sprintf("%0*d", CounterLen, num)), int64(key.offset)); err != nil {
			return "", fmt.Errorf("failed to update keychain: %v", err)
		}

		if err := k.file.Close(); err != nil {
			return "", fmt.Errorf("failed to close keychain file %q: %v", name, err)
		}
	} else {
		// Time-based key
		code, err = otp.Totp(key.raw, time.Now(), key.digits)
		if err != nil {
			return "", fmt.Errorf("failed to get TOTP: %v", err)
		}
	}

	return fmt.Sprintf("%0*d", key.digits, code), nil
}

func ReadKeychain(file *os.File) (Keychain, error) {
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read keychain file: %v", err)
	}

	chain := NewKeychain(file, make(map[string]key), data)

	lines := bytes.SplitAfter(data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		offset += len(line)
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}

		if len(f) >= 3 && len(f[1]) == 1 && '6' <= f[1][0] && f[1][0] <= '8' {
			var key key
			name := string(f[0])
			key.digits = int(f[1][0] - '0')
			raw, err := DecodeKey(string(f[2]))
			if err == nil {
				key.raw = raw
				if len(f) == 3 {
					chain.SetKey(name, key)

					continue
				}

				if len(f) == 4 && len(f[3]) == CounterLen {
					_, err := strconv.ParseUint(string(f[3]), 10, 64)
					if err == nil {
						// Valid counter.
						key.offset = offset - CounterLen
						if line[len(line)-1] == '\n' {
							key.offset--
						}
						chain.SetKey(name, key)

						continue
					}
				}
			}
		}

		log.Printf("%s:%d: malformed key", file.Name(), i+1)
	}

	return chain, nil
}

func DecodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}

	return r
}
