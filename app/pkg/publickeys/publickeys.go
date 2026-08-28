package publickeys

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	defaultHTTPTimeout            = 10 * time.Second
	defaultMinimumTTL             = 5 * time.Minute
	defaultUnknownRefreshInterval = 5 * time.Minute
	maxKeysetBytes                = 1 << 20
)

// Options controls how a remote public-key set is fetched and cached.
type Options struct {
	HTTPClient             *http.Client
	FixedTTL               time.Duration
	MaxTTL                 time.Duration
	UnknownRefreshInterval time.Duration
	Now                    func() time.Time
}

type decoder func(io.Reader) (map[string]*rsa.PublicKey, error)

// Source fetches and caches RSA public keys published under key IDs.
type Source struct {
	url                    string
	client                 *http.Client
	decode                 decoder
	fixedTTL               time.Duration
	minimumTTL             time.Duration
	maxTTL                 time.Duration
	requestTimeout         time.Duration
	unknownRefreshInterval time.Duration
	now                    func() time.Time

	mu                sync.Mutex
	keys              map[string]*rsa.PublicKey
	expiresAt         time.Time
	lastForcedRefresh time.Time
	sf                singleflight.Group
}

// NewJWKS creates a source for a standard RSA JSON Web Key Set.
func NewJWKS(url string, opts Options) *Source {
	return newSource(url, decodeJWKS, opts)
}

// NewX509 creates a source for Google's JSON map of key IDs to PEM certificates.
func NewX509(url string, opts Options) *Source {
	return newSource(url, decodeX509Certificates, opts)
}

func newSource(url string, decode decoder, opts Options) *Source {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	unknownRefreshInterval := opts.UnknownRefreshInterval
	if unknownRefreshInterval == 0 {
		unknownRefreshInterval = defaultUnknownRefreshInterval
	}
	requestTimeout := client.Timeout
	if requestTimeout <= 0 {
		requestTimeout = defaultHTTPTimeout
	}
	return &Source{
		url:                    url,
		client:                 client,
		decode:                 decode,
		fixedTTL:               opts.FixedTTL,
		minimumTTL:             defaultMinimumTTL,
		maxTTL:                 opts.MaxTTL,
		requestTimeout:         requestTimeout,
		unknownRefreshInterval: unknownRefreshInterval,
		now:                    now,
		keys:                   make(map[string]*rsa.PublicKey),
	}
}

// Warm fetches the key set when it is absent or expired.
func (s *Source) Warm(ctx context.Context) error {
	return s.refresh(ctx, false, false)
}

// Key returns the RSA public key matching kid, refreshing for expiry or one
// previously unseen key ID. Unknown-key refreshes are rate-limited so arbitrary
// tokens cannot turn verification into an unbounded outbound request source.
func (s *Source) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(kid) == "" {
		return nil, fmt.Errorf("public key ID is missing")
	}

	s.mu.Lock()
	key, found := s.keys[kid]
	fresh := s.now().Before(s.expiresAt)
	s.mu.Unlock()
	if found && fresh {
		return key, nil
	}

	if err := s.refresh(ctx, fresh, true); err != nil {
		return nil, err
	}

	s.mu.Lock()
	key, found = s.keys[kid]
	s.mu.Unlock()
	if !found {
		return nil, fmt.Errorf("public keyset does not contain a key matching %q", kid)
	}
	return key, nil
}

func (s *Source) refresh(ctx context.Context, force bool, detached bool) error {
	_, err, _ := s.sf.Do("refresh", func() (any, error) {
		now := s.now()
		s.mu.Lock()
		fresh := len(s.keys) > 0 && now.Before(s.expiresAt)
		if !force && fresh {
			s.mu.Unlock()
			return nil, nil
		}
		if force && !s.lastForcedRefresh.IsZero() && now.Sub(s.lastForcedRefresh) < s.unknownRefreshInterval {
			s.mu.Unlock()
			return nil, nil
		}
		if force {
			s.lastForcedRefresh = now
		}
		s.mu.Unlock()

		fetchCtx := ctx
		if detached {
			// A request-time refresh may be shared by unrelated callers. Do not let
			// cancellation of whichever request became the leader abort all coalesced
			// verifications. Keep the refresh bounded even if an injected HTTP client
			// has no timeout of its own.
			var cancel context.CancelFunc
			fetchCtx, cancel = context.WithTimeout(context.Background(), s.requestTimeout)
			defer cancel()
		}
		return nil, s.fetch(fetchCtx)
	})
	return err
}

func (s *Source) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return fmt.Errorf("build public key request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch public key set: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch public key set: unexpected status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysetBytes+1))
	if err != nil {
		return fmt.Errorf("read public key set: %w", err)
	}
	if len(body) > maxKeysetBytes {
		return fmt.Errorf("public key set exceeds %d bytes", maxKeysetBytes)
	}
	keys, err := s.decode(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("parse public key set: %w", err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("public key set did not contain any usable RSA keys")
	}

	ttl := s.fixedTTL
	if ttl == 0 {
		ttl = responseMaxAge(resp.Header.Get("Cache-Control"))
		if ttl < s.minimumTTL {
			ttl = s.minimumTTL
		}
	}
	if s.maxTTL > 0 && ttl > s.maxTTL {
		ttl = s.maxTTL
	}

	now := s.now()
	s.mu.Lock()
	s.keys = keys
	s.expiresAt = now.Add(ttl)
	s.mu.Unlock()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func decodeJWKS(r io.Reader) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(r).Decode(&set); err != nil {
		return nil, err
	}
	result := make(map[string]*rsa.PublicKey)
	for _, key := range set.Keys {
		if key.Kty != "RSA" || (key.Use != "" && key.Use != "sig") {
			continue
		}
		if key.Kid == "" {
			return nil, fmt.Errorf("RSA JWK is missing kid")
		}
		pub, err := decodeRSAPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("decode RSA JWK %q: %w", key.Kid, err)
		}
		result[key.Kid] = pub
	}
	return result, nil
}

func decodeRSAPublicKey(key jwk) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil || len(modulus) == 0 {
		return nil, fmt.Errorf("invalid RSA modulus")
	}
	exponent, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	exp := 0
	for _, b := range exponent {
		exp = exp<<8 | int(b)
	}
	if exp < 2 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exp}, nil
}

func decodeX509Certificates(r io.Reader) (map[string]*rsa.PublicKey, error) {
	certificates := make(map[string]string)
	if err := json.NewDecoder(r).Decode(&certificates); err != nil {
		return nil, err
	}
	result := make(map[string]*rsa.PublicKey, len(certificates))
	for kid, encoded := range certificates {
		if kid == "" {
			return nil, fmt.Errorf("X.509 certificate is missing kid")
		}
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			return nil, fmt.Errorf("decode X.509 certificate %q", kid)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse X.509 certificate %q: %w", kid, err)
		}
		pub, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("X.509 certificate %q does not contain an RSA key", kid)
		}
		result[kid] = pub
	}
	return result, nil
}

func responseMaxAge(cacheControl string) time.Duration {
	for _, directive := range strings.Split(cacheControl, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if !ok || strings.ToLower(name) != "max-age" {
			continue
		}
		seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err == nil && seconds > 0 && seconds <= int64((1<<63-1)/time.Second) {
			return time.Duration(seconds) * time.Second
		}
	}
	return 0
}
