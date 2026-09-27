package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The UI decides what is reachable from the internet, so it gets a password. The hash
// format is self-describing: pbkdf2-sha256.<iterations>.<salt>.<key>, salt and key in
// URL-safe base64. PBKDF2-HMAC-SHA256 is implemented here to keep the binary
// dependency-free.
//
// Separator and alphabet are deliberately not the usual PHC "$" with standard base64.
// This value lives in a .env file that Docker Compose also reads for interpolation, and
// Compose treats "$word" inside it as a variable reference: it warns once and substitutes
// a blank string, so the container receives a truncated hash and every login fails for no
// visible reason. With "." as the separator and URL-safe base64 the whole hash matches
// [A-Za-z0-9._-], which needs no quoting in .env, in YAML or in a shell.
const (
	hashPrefix = "pbkdf2-sha256"
	hashSep    = "."
	iterations = 210000
	keyLen     = 32
	saltLen    = 16
)

// hashEncoding avoids "+" and "/" for the same reason the separator is not "$".
var hashEncoding = base64.RawURLEncoding

func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("Passwort muss mindestens 8 Zeichen haben")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, iterations, keyLen)
	return strings.Join([]string{
		hashPrefix,
		strconv.Itoa(iterations),
		hashEncoding.EncodeToString(salt),
		hashEncoding.EncodeToString(key),
	}, hashSep), nil
}

// ValidateHash reports why a stored hash is unusable, so the gateway can refuse to start
// with a clear message instead of answering every login with 401 forever.
func ValidateHash(hash string) error {
	if strings.TrimSpace(hash) == "" {
		return fmt.Errorf("leer")
	}
	if _, _, _, err := parseHash(hash); err != nil {
		return err
	}
	return nil
}

func parseHash(hash string) (iter int, salt, key []byte, err error) {
	parts := strings.Split(hash, hashSep)
	if len(parts) != 4 || parts[0] != hashPrefix {
		if strings.Contains(hash, "$") {
			return 0, nil, nil, fmt.Errorf("enthaelt \"$\" - Docker Compose ersetzt so etwas in .env " +
				"durch einen Leerstring; Hash neu erzeugen mit \"hash-password\"")
		}
		return 0, nil, nil, fmt.Errorf("Format nicht erkannt, erwartet %s%s<Runden>%s<Salt>%s<Key>",
			hashPrefix, hashSep, hashSep, hashSep)
	}
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter < 1000 {
		return 0, nil, nil, fmt.Errorf("Rundenzahl %q ist unbrauchbar", parts[1])
	}
	if salt, err = hashEncoding.DecodeString(parts[2]); err != nil || len(salt) == 0 {
		return 0, nil, nil, fmt.Errorf("Salt ist kein base64")
	}
	if key, err = hashEncoding.DecodeString(parts[3]); err != nil || len(key) == 0 {
		return 0, nil, nil, fmt.Errorf("Key ist kein base64")
	}
	return iter, salt, key, nil
}

func VerifyPassword(hash, password string) bool {
	iter, salt, want, err := parseHash(hash)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iter, length int) []byte {
	hashLen := sha256.Size
	blocks := (length + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	counter := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(counter, uint32(block))
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(counter)
		u := mac.Sum(nil)
		t := make([]byte, hashLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:length]
}

// throttle slows down and eventually blocks password guessing per source address.
type throttle struct {
	mu       sync.Mutex
	failures map[string]*failureState
}

type failureState struct {
	count   int
	blocked time.Time
	seen    time.Time
}

func newThrottle() *throttle {
	return &throttle{failures: map[string]*failureState{}}
}

func (t *throttle) blockedUntil(remote string) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.failures[remote]
	if f == nil {
		return time.Time{}
	}
	return f.blocked
}

func (t *throttle) fail(remote string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.failures[remote]
	now := time.Now()
	if f == nil || now.Sub(f.seen) > 10*time.Minute {
		f = &failureState{}
		t.failures[remote] = f
	}
	f.count++
	f.seen = now
	if f.count >= 5 {
		f.blocked = now.Add(time.Minute)
	}
	// Keep the map from growing without bound on a long-running gateway.
	if len(t.failures) > 512 {
		for k, v := range t.failures {
			if now.Sub(v.seen) > 10*time.Minute {
				delete(t.failures, k)
			}
		}
	}
}

func (t *throttle) success(remote string) {
	t.mu.Lock()
	delete(t.failures, remote)
	t.mu.Unlock()
}

func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requireAuth wraps a handler in HTTP basic auth. Both user and password are compared
// in constant time; failures are delayed and then blocked.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remote := remoteAddr(r)
		if until := s.throttle.blockedUntil(remote); time.Now().Before(until) {
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
			http.Error(w, "zu viele Fehlversuche", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.user)) == 1
		passOK := VerifyPassword(s.passwordHash, pass)
		if !ok || !userOK || !passOK {
			s.throttle.fail(remote)
			time.Sleep(300 * time.Millisecond)
			w.Header().Set("WWW-Authenticate", `Basic realm="Sunshine Gateway", charset="UTF-8"`)
			http.Error(w, "Anmeldung erforderlich", http.StatusUnauthorized)
			return
		}
		s.throttle.success(remote)
		next(w, r)
	}
}
