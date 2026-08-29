package publickeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeJWKS(t *testing.T, w http.ResponseWriter, keys map[string]*rsa.PublicKey) {
	t.Helper()
	type encodedKey struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	set := struct {
		Keys []encodedKey `json:"keys"`
	}{}
	for kid, key := range keys {
		set.Keys = append(set.Keys, encodedKey{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		})
	}
	if err := json.NewEncoder(w).Encode(set); err != nil {
		t.Error(err)
	}
}

func TestJWKSCacheTTLAndUnknownKeyRefreshCooldown(t *testing.T) {
	key1 := testRSAKey(t)
	key2 := testRSAKey(t)
	now := time.Unix(1_700_000_000, 0)

	var (
		mu   sync.Mutex
		hits int
		keys = map[string]*rsa.PublicKey{"key-1": &key1.PublicKey}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
		w.Header().Set("Cache-Control", "public, max-age=7200")
		writeJWKS(t, w, keys)
	}))
	defer server.Close()
	hitCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return hits
	}

	source := NewJWKS(server.URL, Options{
		HTTPClient:             server.Client(),
		MaxTTL:                 time.Hour,
		UnknownRefreshInterval: 5 * time.Minute,
		Now:                    func() time.Time { return now },
	})
	if err := source.Warm(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Key(context.Background(), "key-1"); err != nil {
		t.Fatal(err)
	}
	if got := hitCount(); got != 1 {
		t.Fatalf("expected one initial fetch, got %d", got)
	}

	mu.Lock()
	keys = map[string]*rsa.PublicKey{"key-2": &key2.PublicKey}
	mu.Unlock()
	if _, err := source.Key(context.Background(), "key-2"); err != nil {
		t.Fatal(err)
	}
	if got := hitCount(); got != 2 {
		t.Fatalf("expected unknown key to force one refresh, got %d fetches", got)
	}
	if _, err := source.Key(context.Background(), "attacker-controlled-kid"); err == nil {
		t.Fatal("expected unknown key error")
	}
	if got := hitCount(); got != 2 {
		t.Fatalf("expected forced refresh cooldown to suppress another fetch, got %d", got)
	}

	now = now.Add(time.Hour + time.Second)
	if _, err := source.Key(context.Background(), "key-2"); err != nil {
		t.Fatal(err)
	}
	if got := hitCount(); got != 3 {
		t.Fatalf("expected capped TTL expiry to refresh keys, got %d fetches", got)
	}
}

func TestExpiredCacheFailsClosed(t *testing.T) {
	key := testRSAKey(t)
	now := time.Unix(1_700_000_000, 0)
	var down atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		writeJWKS(t, w, map[string]*rsa.PublicKey{"key-1": &key.PublicKey})
	}))
	defer server.Close()

	source := NewJWKS(server.URL, Options{HTTPClient: server.Client(), Now: func() time.Time { return now }})
	if _, err := source.Key(context.Background(), "key-1"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(defaultMinimumTTL + time.Second)
	down.Store(true)
	if _, err := source.Key(context.Background(), "key-1"); err == nil {
		t.Fatal("expected expired cache refresh failure")
	}
}

func TestMissingMaxAgeUsesMinimumTTL(t *testing.T) {
	key := testRSAKey(t)
	now := time.Unix(1_700_000_000, 0)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writeJWKS(t, w, map[string]*rsa.PublicKey{"key-1": &key.PublicKey})
	}))
	defer server.Close()

	source := NewJWKS(server.URL, Options{HTTPClient: server.Client(), Now: func() time.Time { return now }})
	if _, err := source.Key(context.Background(), "key-1"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(defaultMinimumTTL - time.Second)
	if _, err := source.Key(context.Background(), "key-1"); err != nil {
		t.Fatal(err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected missing max-age to use minimum TTL, got %d fetches", got)
	}
}

func TestDetachedRefreshUsesExplicitTimeout(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()

	source := NewJWKS(server.URL, Options{HTTPClient: server.Client()})
	source.requestTimeout = 20 * time.Millisecond

	start := time.Now()
	if _, err := source.Key(context.Background(), "key-1"); err == nil {
		t.Fatal("expected detached refresh timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("detached refresh was not bounded: %s", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("expected refresh request to start")
	}
}

func TestX509CertificateMap(t *testing.T) {
	key := testRSAKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "firebase-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]string{"auth-key": certificate})
	}))
	defer server.Close()

	source := NewX509(server.URL, Options{HTTPClient: server.Client()})
	got, err := source.Key(context.Background(), "auth-key")
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Fatal("decoded X.509 key does not match")
	}
}

func TestMalformedKeysetsAreRejected(t *testing.T) {
	tests := []struct {
		name string
		body any
		new  func(string, Options) *Source
	}{
		{"empty JWKS", map[string]any{"keys": []any{}}, NewJWKS},
		{"malformed RSA JWK", map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "bad", "use": "sig", "n": "!", "e": "AQAB"}}}, NewJWKS},
		{"malformed X.509", map[string]string{"bad": "not PEM"}, NewX509},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(tc.body)
			}))
			defer server.Close()
			source := tc.new(server.URL, Options{HTTPClient: server.Client()})
			if err := source.Warm(context.Background()); err == nil {
				t.Fatal("expected malformed keyset error")
			}
		})
	}
}
