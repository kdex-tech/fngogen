package kdexauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchange_PostsRFC8693FormAndReturnsAccessToken(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"minted.jwt.for.b","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()

	tok, err := Exchange(context.Background(), Config{
		TokenEndpoint: srv.URL,
		SubjectToken:  "the.inbound.fat",
	}, "/v1/internal")

	require.NoError(t, err)
	assert.Equal(t, "minted.jwt.for.b", tok)
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", gotForm.Get("grant_type"))
	assert.Equal(t, "the.inbound.fat", gotForm.Get("subject_token"))
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", gotForm.Get("subject_token_type"))
	assert.Equal(t, "/v1/internal", gotForm.Get("resource"))
}

func TestExchange_NonJSONOrErrorStatusReturnsError(t *testing.T) {
	t.Run("error status with JSON error body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_target"}`))
		}))
		defer srv.Close()

		tok, err := Exchange(context.Background(), Config{
			TokenEndpoint: srv.URL,
			SubjectToken:  "the.inbound.fat",
		}, "/v1/internal")

		require.Error(t, err)
		assert.Empty(t, tok)
		assert.Contains(t, err.Error(), "invalid_target")
	})

	t.Run("non-JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()

		tok, err := Exchange(context.Background(), Config{
			TokenEndpoint: srv.URL,
			SubjectToken:  "the.inbound.fat",
		}, "/v1/internal")

		require.Error(t, err)
		assert.Empty(t, tok)
	})
}

func TestExchange_EmptyTokenEndpointOrResourceIsError(t *testing.T) {
	t.Run("empty token endpoint", func(t *testing.T) {
		tok, err := Exchange(context.Background(), Config{
			TokenEndpoint: "",
			SubjectToken:  "x",
		}, "/v1/foo")

		require.Error(t, err)
		assert.Empty(t, tok)
	})

	t.Run("empty resource", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"should.not.be.reached"}`))
		}))
		defer srv.Close()

		tok, err := Exchange(context.Background(), Config{
			TokenEndpoint: srv.URL,
			SubjectToken:  "x",
		}, "")

		require.Error(t, err)
		assert.Empty(t, tok)
	})
}

func TestExchange_EmptyAccessTokenOn200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tok, err := Exchange(context.Background(), Config{
		TokenEndpoint: srv.URL,
		SubjectToken:  "the.inbound.fat",
	}, "/v1/internal")

	require.Error(t, err)
	assert.Empty(t, tok)
}

func TestExchange_EmptySubjectTokenIsError(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"should.not.be.reached"}`))
	}))
	defer srv.Close()

	tok, err := Exchange(context.Background(), Config{
		TokenEndpoint: srv.URL,
		SubjectToken:  "",
	}, "/v1/internal")

	require.Error(t, err)
	assert.Empty(t, tok)
	assert.False(t, called, "no HTTP call should be made when subject token is empty")
}
