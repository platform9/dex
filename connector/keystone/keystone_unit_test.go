package keystone

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dexidp/dex/connector"
)

func TestGetRoleAssignments_IncludeNames(t *testing.T) {
	var gotUserQuery, gotGroupQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "user.id=") {
			gotUserQuery = r.URL.RawQuery
		}
		if strings.Contains(r.URL.RawQuery, "group.id=") {
			gotGroupQuery = r.URL.RawQuery
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			RoleAssignments []roleAssignment `json:"role_assignments"`
		}{})
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))

	if _, err := getRoleAssignments(t.Context(), ts.Client(), ts.URL, "tok", getRoleAssignmentsOptions{userID: "u1"}, logger); err != nil {
		t.Fatalf("getRoleAssignments (userID) error: %v", err)
	}
	if _, err := getRoleAssignments(t.Context(), ts.Client(), ts.URL, "tok", getRoleAssignmentsOptions{groupID: "g1"}, logger); err != nil {
		t.Fatalf("getRoleAssignments (groupID) error: %v", err)
	}

	unescapedUserQuery, err := url.QueryUnescape(gotUserQuery)
	if err != nil {
		t.Fatalf("failed to unescape user query: %v", err)
	}
	if !strings.Contains(unescapedUserQuery, "include_names") {
		t.Fatalf("expected include_names in user.id request, got query: %q", gotUserQuery)
	}
	unescapedGroupQuery, err := url.QueryUnescape(gotGroupQuery)
	if err != nil {
		t.Fatalf("failed to unescape group query: %v", err)
	}
	if !strings.Contains(unescapedGroupQuery, "include_names") {
		t.Fatalf("expected include_names in group.id request, got query: %q", gotGroupQuery)
	}
}

func TestGetRoleAssignments_ProjectIDFilter(t *testing.T) {
	var gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			RoleAssignments []roleAssignment `json:"role_assignments"`
		}{})
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))

	if _, err := getRoleAssignments(t.Context(), ts.Client(), ts.URL, "tok", getRoleAssignmentsOptions{userID: "u1", projectID: "proj-1"}, logger); err != nil {
		t.Fatalf("getRoleAssignments (userID+projectID) error: %v", err)
	}

	unescaped, err := url.QueryUnescape(gotQuery)
	if err != nil {
		t.Fatalf("failed to unescape query: %v", err)
	}
	if !strings.Contains(unescaped, "scope.project.id=proj-1") {
		t.Fatalf("expected scope.project.id=proj-1 in request, got query: %q", gotQuery)
	}
	if !strings.Contains(unescaped, "user.id=u1") {
		t.Fatalf("expected user.id=u1 in request, got query: %q", gotQuery)
	}

	// projectID also narrows a group-scoped lookup.
	gotQuery = ""
	if _, err := getRoleAssignments(t.Context(), ts.Client(), ts.URL, "tok", getRoleAssignmentsOptions{groupID: "g1", projectID: "proj-1"}, logger); err != nil {
		t.Fatalf("getRoleAssignments (groupID+projectID) error: %v", err)
	}
	unescaped, err = url.QueryUnescape(gotQuery)
	if err != nil {
		t.Fatalf("failed to unescape query: %v", err)
	}
	if !strings.Contains(unescaped, "scope.project.id=proj-1") {
		t.Fatalf("expected scope.project.id=proj-1 in a group.id lookup too, got query: %q", gotQuery)
	}
	if !strings.Contains(unescaped, "group.id=g1") {
		t.Fatalf("expected group.id=g1 in request, got query: %q", gotQuery)
	}
}

// multiScopeHandler serves the minimal set of Keystone endpoints
// getAllGroupsForUser needs, returning one project-scoped, one
// domain-scoped, and one system-scoped role assignment for the same user.
func multiScopeHandler(t *testing.T, projectDomainName string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v3/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{})
			return
		case strings.Contains(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{})
			return
		case strings.HasSuffix(r.URL.Path, "/v3/role_assignments"):
			body := `{
				"role_assignments": [
					{
						"scope": {"project": {"id": "proj-1", "name": "My_Project", "domain": {"id": "dom-1", "name": "` + projectDomainName + `"}}},
						"user": {"id": "u1"},
						"role": {"id": "role-admin", "name": "admin"}
					},
					{
						"scope": {"domain": {"id": "dom-2", "name": "Customer_Domain"}, "OS-INHERIT:inherited_to": "projects"},
						"user": {"id": "u1"},
						"role": {"id": "role-cda", "name": "customer_domain_admin"}
					},
					{
						"scope": {"system": {"all": true}},
						"user": {"id": "u1"},
						"role": {"id": "role-pa", "name": "platform_admin"}
					}
				]
			}`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestGetAllGroupsForUser_MultiScopeDispatch(t *testing.T) {
	ts := httptest.NewServer(multiScopeHandler(t, "Cust_Domain"))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "login-domain", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := map[string]bool{
		"cust-cust-domain-my-project-admin":          true, // 4-part project group
		"cust-customer-domain-customer_domain_admin": true, // 3-part domain group
		"cust-platform_admin":                        true, // 2-part system group
	}
	if len(groups) != len(want) {
		t.Fatalf("unexpected groups: got %v, want keys %v", groups, want)
	}
	for _, g := range groups {
		if !want[g] {
			t.Errorf("unexpected group %q in result %v", g, groups)
		}
	}
}

func TestGetAllGroupsForUser_ProjectOnlyUsesRowDomainNotConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v3/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{})
			return
		case strings.Contains(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{})
			return
		case strings.HasSuffix(r.URL.Path, "/v3/role_assignments"):
			body := `{
				"role_assignments": [
					{
						"scope": {"project": {"id": "proj-1", "name": "myproject", "domain": {"id": "dom-1", "name": "RowDomain"}}},
						"user": {"id": "u1"},
						"role": {"id": "role-admin", "name": "admin"}
					}
				]
			}`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	// Pass a DIFFERENT domainID (the connector's configured login domain)
	// than the row's own scope.project.domain.name, to prove the row's
	// data wins, not the config value.
	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "login-domain", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := "cust-rowdomain-myproject-admin"
	if len(groups) != 1 || groups[0] != want {
		t.Fatalf("unexpected groups: got %v, want [%q]", groups, want)
	}
}

func TestGetAllGroupsForUser_ProjectIDNarrowsProjectScopeOnly(t *testing.T) {
	var gotUserRoleAssignmentsQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v3/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{})
			return
		case strings.Contains(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{})
			return
		case strings.HasSuffix(r.URL.Path, "/v3/role_assignments"):
			if strings.Contains(r.URL.RawQuery, "user.id=") {
				gotUserRoleAssignmentsQuery = r.URL.RawQuery
			}
			// Simulates Keystone already applying scope.project.id=proj-1.
			body := `{
				"role_assignments": [
					{
						"scope": {"project": {"id": "proj-1", "name": "my-project", "domain": {"id": "dom-1", "name": "cust-domain"}}},
						"user": {"id": "u1"},
						"role": {"id": "role-admin", "name": "admin"}
					},
					{
						"scope": {"domain": {"id": "dom-2", "name": "Customer_Domain"}},
						"user": {"id": "u1"},
						"role": {"id": "role-cda", "name": "customer_domain_admin"}
					},
					{
						"scope": {"system": {"all": true}},
						"user": {"id": "u1"},
						"role": {"id": "role-pa", "name": "platform_admin"}
					}
				]
			}`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "login-domain", "proj-1", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	unescaped, err := url.QueryUnescape(gotUserRoleAssignmentsQuery)
	if err != nil {
		t.Fatalf("failed to unescape query: %v", err)
	}
	if !strings.Contains(unescaped, "scope.project.id=proj-1") {
		t.Fatalf("expected the user role_assignments query to include scope.project.id=proj-1, got: %q", gotUserRoleAssignmentsQuery)
	}

	want := map[string]bool{
		"cust-cust-domain-my-project-admin":          true, // project-scoped, matches the requested project
		"cust-customer-domain-customer_domain_admin": true, // domain-scoped, always included regardless of project_id
		"cust-platform_admin":                        true, // system-scoped, always included regardless of project_id
	}
	if len(groups) != len(want) {
		t.Fatalf("unexpected groups: got %v, want keys %v", groups, want)
	}
	for _, g := range groups {
		if !want[g] {
			t.Errorf("unexpected group %q in result %v", g, groups)
		}
	}
}

func TestGenerateGroupName(t *testing.T) {
	p := projectScope{Name: "My_Project", Domain: namedIdentifier{Name: "My_Domain"}}
	role := namedIdentifier{Name: "_member_"}
	got := generateGroupName(p, role, "cust")
	want := "cust-my-domain-my-project-member"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGenerateDomainGroupName(t *testing.T) {
	domain := namedIdentifier{Name: "Customer_Domain"}
	role := namedIdentifier{Name: "customer_domain_admin"}
	got := generateDomainGroupName(domain, role, "cust")
	want := "cust-customer-domain-customer_domain_admin"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGenerateSystemGroupName(t *testing.T) {
	role := namedIdentifier{Name: "_member_"}
	got := generateSystemGroupName(role, "cust")
	want := "cust-member"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// authenticateRequestBody mirrors the subset of loginRequestData this test
// needs to inspect.
type authenticateRequestBody struct {
	Auth struct {
		Identity struct {
			Password struct {
				User struct {
					Name   string         `json:"name"`
					Domain domainKeystone `json:"domain"`
				} `json:"user"`
			} `json:"password"`
		} `json:"identity"`
	} `json:"auth"`
}

func newAuthenticateStubServer(t *testing.T, capture *authenticateRequestBody) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(capture); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		w.Header().Set("X-Subject-Token", "tok")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tokenResponse{Token: tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}})
	}))
}

func TestAuthenticate_DomainIDOverridesDefault(t *testing.T) {
	var got authenticateRequestBody
	ts := newAuthenticateStubServer(t, &got)
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	// Domain is the admin account's domain, unrelated to end-user login.
	p := &conn{
		Domain: domainKeystone{Name: "admin-account-domain"},
		Host:   ts.URL,
		client: ts.Client(),
		Logger: logger,
	}

	if _, _, err := p.authenticate(t.Context(), "user1", "pass", connector.Scopes{DomainID: "request-domain"}); err != nil {
		t.Fatalf("authenticate error: %v", err)
	}

	if got.Auth.Identity.Password.User.Domain.ID != "request-domain" {
		t.Fatalf("expected request domain ID to be used, got domain=%+v", got.Auth.Identity.Password.User.Domain)
	}
	if got.Auth.Identity.Password.User.Domain.Name != "" {
		t.Fatalf("expected only Domain.ID to be set when DomainID is supplied, got domain=%+v", got.Auth.Identity.Password.User.Domain)
	}
}

func TestAuthenticate_FallsBackToDefaultDomainWhenAbsent(t *testing.T) {
	var got authenticateRequestBody
	ts := newAuthenticateStubServer(t, &got)
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	// Domain is the admin account's domain, unrelated to end-user login.
	p := &conn{
		Domain: domainKeystone{Name: "admin-account-domain"},
		Host:   ts.URL,
		client: ts.Client(),
		Logger: logger,
	}

	if _, _, err := p.authenticate(t.Context(), "user1", "pass", connector.Scopes{}); err != nil {
		t.Fatalf("authenticate error: %v", err)
	}

	if got.Auth.Identity.Password.User.Domain.ID != defaultUserDomainID {
		t.Fatalf("expected fallback to %q, got domain=%+v", defaultUserDomainID, got.Auth.Identity.Password.User.Domain)
	}
	if got.Auth.Identity.Password.User.Domain.Name == "admin-account-domain" {
		t.Fatalf("Config.Domain (admin account's domain) must never be used for end-user login, got domain=%+v", got.Auth.Identity.Password.User.Domain)
	}
}

func TestGetAdminTokenUnscoped_UsesConfiguredAdminDomain(t *testing.T) {
	var got authenticateRequestBody
	ts := newAuthenticateStubServer(t, &got)
	defer ts.Close()

	adminDomain := domainKeystone{Name: "admin-account-domain"}
	if _, err := getAdminTokenUnscoped(t.Context(), ts.Client(), ts.URL, "admin", "adminpass", adminDomain); err != nil {
		t.Fatalf("getAdminTokenUnscoped error: %v", err)
	}

	if got.Auth.Identity.Password.User.Domain.Name != "admin-account-domain" {
		t.Fatalf("expected admin token request to use the configured admin domain, got domain=%+v", got.Auth.Identity.Password.User.Domain)
	}
	if got.Auth.Identity.Password.User.Domain.Name == "Default" {
		t.Fatalf("admin domain must not be hardcoded to \"Default\", got domain=%+v", got.Auth.Identity.Password.User.Domain)
	}
}
