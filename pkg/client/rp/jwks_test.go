package rp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tu "github.com/zitadel/oidc/v3/internal/testutil"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestJsonWebKeySet_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		wantKeyLen int
		wantErr    bool
		errPrefix  string
	}{
		{
			name:       "valid key set",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "empty key set",
			jsonData:   `{"keys":[]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "unknown key type",
			jsonData:   `{"keys":[{"kty":"UNKNOWN","use":"sig","kid":"key1"}]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "mixed valid and unknown key types",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"},{"kty":"UNKNOWN","use":"sig","kid":"key2"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "invalid json",
			jsonData:   `{"keys":[{]`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshall key set: ",
		},
		{
			name:       "other error during key unmarshal",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256"}]}`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshal key 0 from set: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keySet jsonWebKeySet
			err := keySet.UnmarshalJSON([]byte(tt.jsonData))

			if tt.wantErr {
				assert.Error(t, err)
				assert.NotErrorIs(t, err, jose.ErrUnsupportedKeyType)
				assert.True(t, strings.HasPrefix(err.Error(), tt.errPrefix))

			} else {
				assert.NoError(t, err)
				assert.Len(t, keySet.Keys, tt.wantKeyLen)
			}
		})
	}
}

func TestRemoteKeySet_VerifySignature_WrapsFetchError(t *testing.T) {
	errTransport := errors.New("connection refused")

	tests := []struct {
		name      string
		transport roundTripFunc
		wantErr   error
	}{
		{
			name: "transport error",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errTransport
			},
			wantErr: errTransport,
		},
		{
			name: "response too large",
			transport: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat(" ", int(httphelper.MaxResponseBodySize)+1))),
					Request:    r,
				}, nil
			},
			wantErr: httphelper.ErrResponseBodyTooLarge,
		},
		{
			name: "oauth error response",
			transport: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Body:       io.NopCloser(strings.NewReader(`{"error":"server_error","error_description":"key store unavailable"}`)),
					Request:    r,
				}, nil
			},
			wantErr: &oidc.Error{ErrorType: oidc.ServerError, Description: "key store unavailable"},
		},
	}

	payload, err := tu.Signer.Sign([]byte(`{"sub":"subject"}`))
	require.NoError(t, err)
	token, err := payload.CompactSerialize()
	require.NoError(t, err)
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{tu.SignatureAlgorithm})
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keySet := NewRemoteKeySet(&http.Client{Transport: tt.transport}, "https://example.com/keys")
			_, err := keySet.VerifySignature(context.Background(), jws)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestRemoteKeySet_FirstCallerCancelDoesNotPoisonWaiters verifies that when
// the caller that started the shared inflight key fetch cancels its context,
// the fetch itself keeps running and all other waiters still receive the
// fetched keys.
func TestRemoteKeySet_FirstCallerCancelDoesNotPoisonWaiters(t *testing.T) {
	payload, err := tu.Signer.Sign([]byte(`{"sub":"subject"}`))
	require.NoError(t, err)
	token, err := payload.CompactSerialize()
	require.NoError(t, err)
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{tu.SignatureAlgorithm})
	require.NoError(t, err)

	keySetJSON, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{tu.WebKey.Public()}})
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(keySetJSON))),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    r,
		}, nil
	})
	keySet := NewRemoteKeySet(&http.Client{Transport: transport}, "https://example.com/keys")

	type result struct {
		payload []byte
		err     error
	}

	// First caller: starts the shared inflight fetch, then gets canceled.
	ctx1, cancel1 := context.WithCancel(context.Background())
	res1 := make(chan result, 1)
	go func() {
		p, err := keySet.VerifySignature(ctx1, jws)
		res1 <- result{p, err}
	}()

	// Wait until the fetch is actually in flight, then register more waiters
	// on the same inflight request.
	<-entered
	const waiters = 8
	waiterRes := make(chan result, waiters)
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := keySet.VerifySignature(context.Background(), jws)
			waiterRes <- result{p, err}
		}()
	}
	// Give the waiters a chance to attach to the inflight request.
	time.Sleep(100 * time.Millisecond)

	// Cancel the first caller: its wait must abort, but the shared fetch and
	// all other waiters must not be affected.
	cancel1()
	select {
	case r := <-res1:
		require.ErrorIs(t, r.err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("first caller did not return after context cancellation")
	}

	// Let the fetch complete; every waiter must get the verified payload.
	close(release)
	want, err := jws.Verify(tu.WebKey.Public())
	require.NoError(t, err)
	wg.Wait()
	for i := 0; i < waiters; i++ {
		r := <-waiterRes
		require.NoError(t, r.err)
		assert.Equal(t, want, r.payload)
	}

	// The fetch must have been shared: exactly one HTTP call for all callers.
	assert.Equal(t, int32(1), calls.Load())
}
