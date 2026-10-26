// Package kdexauth provides the client half of KDex FAT token exchange
// (RFC 8693): a function handler trades its inbound Function Access Token for a
// token addressed to another function's audience, so it can call that function
// directly in-cluster.
package kdexauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	// TokenEndpoint is the host token endpoint, e.g. os.Getenv("ISSUER")+"/-/token".
	TokenEndpoint string
	// SubjectToken is the raw inbound FAT (from RequestTokenFromContext).
	SubjectToken string
	// HTTPClient is optional; http.DefaultClient is used when nil.
	HTTPClient *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangedToken is the result of a successful token exchange.
type ExchangedToken struct {
	// AccessToken is the minted JWT addressed to the target function's audience.
	AccessToken string
	// ExpiresIn is the token's lifetime in seconds, as reported by the token
	// endpoint's expires_in. It is 0 when the endpoint omits the field; callers
	// caching the token should treat 0 as "unknown" and fall back to a
	// conservative horizon (or the token's own exp claim) rather than caching
	// indefinitely.
	ExpiresIn int
}

// Exchange trades cfg.SubjectToken for a JWT addressed to `resource`'s function.
func Exchange(ctx context.Context, cfg Config, resource string) (ExchangedToken, error) {
	if cfg.SubjectToken == "" {
		return ExchangedToken{}, fmt.Errorf("kdexauth: empty subject token; no authenticated request context")
	}
	if cfg.TokenEndpoint == "" || resource == "" {
		return ExchangedToken{}, fmt.Errorf("kdexauth: token endpoint and resource are required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {cfg.SubjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {resource},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ExchangedToken{}, fmt.Errorf("kdexauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return ExchangedToken{}, fmt.Errorf("kdexauth: token exchange request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return ExchangedToken{}, fmt.Errorf("kdexauth: decode token response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		return ExchangedToken{}, fmt.Errorf("kdexauth: token exchange failed (status %d): %s %s", resp.StatusCode, tr.Error, tr.ErrorDesc)
	}
	return ExchangedToken{AccessToken: tr.AccessToken, ExpiresIn: tr.ExpiresIn}, nil
}
