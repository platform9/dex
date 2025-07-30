package keystonefed

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// testLogger is a simple implementation of log.Logger for testing
type testLogger struct{}

func (l testLogger) Debug(args ...interface{})                 {}
func (l testLogger) Info(args ...interface{})                  {}
func (l testLogger) Warn(args ...interface{})                  {}
func (l testLogger) Error(args ...interface{})                 {}
func (l testLogger) Debugf(format string, args ...interface{}) {}
func (l testLogger) Infof(format string, args ...interface{})  {}
func (l testLogger) Warnf(format string, args ...interface{})  {}
func (l testLogger) Errorf(format string, args ...interface{}) {}

func TestFlowMinimal(t *testing.T) {
	mux := http.NewServeMux()

	// GET /v3/auth/tokens and POST /v3/auth/tokens
	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(authTokensResp{
				Token: struct {
					User struct {
						ID     string "json:\"id\""
						Name   string "json:\"name\""
						Email  string "json:\"email\""
						Domain struct {
							ID string "json:\"id\""
						} "json:\"domain\""
					} "json:\"user\""
					Project struct {
						ID string "json:\"id\""
					} "json:\"project\""
				}{
					User: struct {
						ID     string "json:\"id\""
						Name   string "json:\"name\""
						Email  string "json:\"email\""
						Domain struct {
							ID string "json:\"id\""
						} "json:\"domain\""
					}{
						ID:    "u123",
						Name:  "alice",
						Email: "alice@example.com",
						Domain: struct {
							ID string "json:\"id\""
						}{
							ID: "default",
						},
					},
					Project: struct {
						ID string "json:\"id\""
					}{
						ID: "p123",
					},
				},
			})
		case "POST":
			// scope token
			w.Header().Set("X-Subject-Token", "scoped-token")
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /v3/groups
	mux.HandleFunc("/v3/groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(groupsResp{
			Groups: []struct {
				ID   string "json:\"id\""
				Name string "json:\"name\""
			}{
				{ID: "g1", Name: "admins"},
				{ID: "g2", Name: "devs"},
			},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Create a test logger that satisfies the log.Logger interface
	logger := log.Logger(testLogger{})

	conn, err := New(Config{
		BaseURL:            ts.URL,
		IdentityProviderID: "foo",
		ProtocolID:         "saml2",
		TokenInQuery:       true,
		ProjectID:          "p123",
	}, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	req := httptest.NewRequest("GET", "/callback?state=xyz&ks_token=unscoped-token", nil)
	ident, err := conn.HandleCallback(connector.Scopes{Groups: true}, req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if ident.UserID != "u123" || len(ident.Groups) != 2 {
		t.Fatalf("unexpected ident: %#v", ident)
	}
}
