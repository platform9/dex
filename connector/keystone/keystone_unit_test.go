package keystone

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "login-domain", info, logger)
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
	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "login-domain", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := "cust-rowdomain-myproject-admin"
	if len(groups) != 1 || groups[0] != want {
		t.Fatalf("unexpected groups: got %v, want [%q]", groups, want)
	}
}

// effectiveDropsSystemScopeHandler mimics real Keystone behavior observed against
// a live deployment: a GET /v3/role_assignments?user.id=... request without
// "effective" returns a system-scoped assignment, but the same request with
// "effective" set silently omits it (system-scoped assignments have no
// project/domain to expand into). The connector must merge both queries so
// system-scoped roles aren't lost.
func effectiveDropsSystemScopeHandler(t *testing.T) http.HandlerFunc {
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
			w.WriteHeader(http.StatusOK)
			if strings.Contains(r.URL.RawQuery, "effective") {
				_, _ = w.Write([]byte(`{
					"role_assignments": [
						{
							"scope": {"project": {"id": "proj-1", "name": "My_Project", "domain": {"id": "dom-1", "name": "Cust_Domain"}}},
							"user": {"id": "u1"},
							"role": {"id": "role-admin", "name": "admin"}
						}
					]
				}`))
				return
			}
			_, _ = w.Write([]byte(`{
				"role_assignments": [
					{
						"scope": {"project": {"id": "proj-1", "name": "My_Project", "domain": {"id": "dom-1", "name": "Cust_Domain"}}},
						"user": {"id": "u1"},
						"role": {"id": "role-admin", "name": "admin"}
					},
					{
						"scope": {"system": {"all": true}},
						"user": {"id": "u1"},
						"role": {"id": "role-pa", "name": "platform_admin"}
					}
				]
			}`))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestGetAllGroupsForUser_EffectiveDoesNotDropSystemScope(t *testing.T) {
	ts := httptest.NewServer(effectiveDropsSystemScopeHandler(t))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "login-domain", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := map[string]bool{
		"cust-cust-domain-my-project-admin": true,
		"cust-platform_admin":               true,
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
