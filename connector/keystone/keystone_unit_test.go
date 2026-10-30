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
	// getRoleAssignments makes one unfiltered request (scope.project.id is
	// never sent) and filters client-side, since Keystone's server-side
	// filter would also drop domain-/system-scoped rows.
	var callCount int
	var gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(allRoleAssignmentsBody))
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))

	ras, err := getRoleAssignments(t.Context(), ts.Client(), ts.URL, "tok", getRoleAssignmentsOptions{userID: "u1", projectID: "proj-1"}, logger)
	if err != nil {
		t.Fatalf("getRoleAssignments (userID+projectID) error: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected exactly 1 request, got %d", callCount)
	}
	unescaped, err := url.QueryUnescape(gotQuery)
	if err != nil {
		t.Fatalf("failed to unescape query: %v", err)
	}
	if strings.Contains(unescaped, "scope.project.id=") {
		t.Fatalf("expected no scope.project.id in the request (filtering is client-side), got: %q", gotQuery)
	}
	if !strings.Contains(unescaped, "user.id=u1") {
		t.Fatalf("expected user.id=u1 in request, got: %q", gotQuery)
	}

	// allRoleAssignmentsBody has one project-scoped (proj-1), one
	// domain-scoped, one system-scoped row — all three should survive.
	if len(ras) != 3 {
		t.Fatalf("expected all 3 rows (project-1 matches, domain/system always kept), got %d: %+v", len(ras), ras)
	}
}

func TestGetRoleAssignments_ProjectIDDropsOtherProjects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body := `{
			"role_assignments": [
				{
					"scope": {"project": {"id": "proj-1", "name": "my-project"}},
					"user": {"id": "u1"},
					"role": {"id": "role-admin", "name": "admin"}
				},
				{
					"scope": {"project": {"id": "other-proj", "name": "other-project"}},
					"user": {"id": "u1"},
					"role": {"id": "role-admin", "name": "admin"}
				},
				{
					"scope": {"system": {"all": true}},
					"user": {"id": "u1"},
					"role": {"id": "role-3", "name": "role3"}
				}
			]
		}`
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	ras, err := getRoleAssignments(t.Context(), ts.Client(), ts.URL, "tok", getRoleAssignmentsOptions{userID: "u1", projectID: "proj-1"}, logger)
	if err != nil {
		t.Fatalf("getRoleAssignments error: %v", err)
	}

	if len(ras) != 2 {
		t.Fatalf("expected 2 rows (proj-1 + system, other-proj dropped), got %d: %+v", len(ras), ras)
	}
	for _, ra := range ras {
		if ra.Scope.Project != nil && ra.Scope.Project.ID != "proj-1" {
			t.Errorf("unexpected project row leaked through: %+v", ra)
		}
	}
}

func TestGetRoleAssignments_NoFilteringWithoutProjectID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "scope.project.id=") {
			t.Errorf("did not expect scope.project.id in request: %q", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(allRoleAssignmentsBody))
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	ras, err := getRoleAssignments(t.Context(), ts.Client(), ts.URL, "tok", getRoleAssignmentsOptions{userID: "u1"}, logger)
	if err != nil {
		t.Fatalf("getRoleAssignments error: %v", err)
	}
	if len(ras) != 3 {
		t.Fatalf("expected all 3 rows unfiltered, got %d: %+v", len(ras), ras)
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
						"scope": {"domain": {"id": "dom-2", "name": "Second_Domain"}, "OS-INHERIT:inherited_to": "projects"},
						"user": {"id": "u1"},
						"role": {"id": "role-2", "name": "role2"}
					},
					{
						"scope": {"system": {"all": true}},
						"user": {"id": "u1"},
						"role": {"id": "role-3", "name": "role3"}
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

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := map[string]bool{
		"cust-cust-domain-my-project-admin": true, // 4-part project group
		"cust-proj-1-admin":                 true, // project ID group
		"cust-second-domain-role2":          true, // 3-part domain group
		"cust-role3":                        true, // 2-part system group
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

func TestGetAllGroupsForUser_ProjectGroupUsesRowDomain(t *testing.T) {
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

	// Project group names use the role assignment's own
	// scope.project.domain.name, not any connector-level config.
	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := []string{"cust-rowdomain-myproject-admin", "cust-proj-1-admin"}
	if len(groups) != len(want) || groups[0] != want[0] || groups[1] != want[1] {
		t.Fatalf("unexpected groups: got %v, want %q", groups, want)
	}
}

// allRoleAssignments is the fixed set of role assignments a fake Keystone
// in these tests holds for user u1: one project-scoped, one domain-scoped,
// one system-scoped.
const allRoleAssignmentsBody = `{
	"role_assignments": [
		{
			"scope": {"project": {"id": "proj-1", "name": "my-project", "domain": {"id": "dom-1", "name": "cust-domain"}}},
			"user": {"id": "u1"},
			"role": {"id": "role-admin", "name": "admin"}
		},
		{
			"scope": {"domain": {"id": "dom-2", "name": "Second_Domain"}},
			"user": {"id": "u1"},
			"role": {"id": "role-2", "name": "role2"}
		},
		{
			"scope": {"system": {"all": true}},
			"user": {"id": "u1"},
			"role": {"id": "role-3", "name": "role3"}
		}
	]
}`

func TestGetAllGroupsForUser_ProjectIDStillIncludesDomainAndSystemRoles(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/v3/projects/"):
			w.WriteHeader(http.StatusOK)
			return
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
			_, _ = w.Write([]byte(allRoleAssignmentsBody))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "proj-1", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := map[string]bool{
		"cust-cust-domain-my-project-admin": true, // project-scoped, matches the requested project
		"cust-proj-1-admin":                 true, // project ID group for the requested project
		"cust-second-domain-role2":          true, // domain-scoped, must still appear
		"cust-role3":                        true, // system-scoped, must still appear
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

func TestGetAllGroupsForUser_ProjectIDExcludesOtherProjects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/v3/projects/"):
			w.WriteHeader(http.StatusOK)
			return
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
			body := `{
				"role_assignments": [
					{
						"scope": {"project": {"id": "other-proj", "name": "other-project", "domain": {"id": "dom-1", "name": "cust-domain"}}},
						"user": {"id": "u1"},
						"role": {"id": "role-admin", "name": "admin"}
					},
					{
						"scope": {"system": {"all": true}},
						"user": {"id": "u1"},
						"role": {"id": "role-3", "name": "role3"}
					}
				]
			}`
			_, _ = w.Write([]byte(body))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "proj-1", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := map[string]bool{
		"cust-role3": true, // system-scoped, must still appear
	}
	if len(groups) != len(want) {
		t.Fatalf("unexpected groups: got %v, want keys %v (other-project's role must be excluded)", groups, want)
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

func TestGenerateProjectIDGroupName(t *testing.T) {
	p := projectScope{ID: "8f3a9b2c4d5e6f708192a3b4c5d6e7f8"}
	role := namedIdentifier{Name: "_member_"}
	got := generateProjectIDGroupName(p, role, "cust")
	want := "cust-8f3a9b2c-member"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGenerateProjectIDGroupName_HyphenatedRole(t *testing.T) {
	p := projectScope{ID: "8f3a9b2c4d5e6f708192a3b4c5d6e7f8"}
	role := namedIdentifier{Name: "dev-admin"}
	got := generateProjectIDGroupName(p, role, "cust")
	want := "cust-8f3a9b2c-dev.admin"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGetAllGroupsForUser_HyphenatedRoleCannotSpoofProjectIDGroup(t *testing.T) {
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
						"scope": {"project": {"id": "8f3a9b2c4d5e6f708192a3b4c5d6e7f8", "name": "dev", "domain": {"id": "dom-1", "name": "default"}}},
						"user": {"id": "u1"},
						"role": {"id": "role-cm", "name": "custom-member"}
					},
					{
						"scope": {"system": {"all": true}},
						"user": {"id": "u1"},
						"role": {"id": "role-spoof", "name": "8f3a9b2c-admin"}
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

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := map[string]bool{
		"cust-default-dev-custom.member": true, // 4-part project group
		"cust-8f3a9b2c-custom.member":    true, // project ID group
		"cust-8f3a9b2c.admin":            true, // system group
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

func TestGenerateDomainGroupName(t *testing.T) {
	domain := namedIdentifier{Name: "Second_Domain"}
	role := namedIdentifier{Name: "role2"}
	got := generateDomainGroupName(domain, role, "cust")
	want := "cust-second-domain-role2"
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
		t.Fatalf("Config.Domain must never be used for end-user login, got domain=%+v", got.Auth.Identity.Password.User.Domain)
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

func TestProjectExists(t *testing.T) {
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if strings.HasSuffix(r.URL.Path, "/v3/projects/proj-1") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	ok, err := projectExists(t.Context(), ts.Client(), ts.URL, "tok", "proj-1")
	if err != nil {
		t.Fatalf("projectExists error: %v", err)
	}
	if !ok {
		t.Fatalf("expected project to exist")
	}
	if !strings.HasSuffix(gotPath, "/v3/projects/proj-1") {
		t.Fatalf("expected request to /v3/projects/proj-1, got path: %q", gotPath)
	}

	ok, err = projectExists(t.Context(), ts.Client(), ts.URL, "tok", "bogus-id")
	if err != nil {
		t.Fatalf("projectExists error: %v", err)
	}
	if ok {
		t.Fatalf("expected project to not exist")
	}
}

func TestGetAllGroupsForUser_FailsWhenProjectIDDoesNotExist(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v3/projects/bogus-id") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		t.Fatalf("unexpected request to %s — role_assignments/groups should not be fetched when the project doesn't exist", r.URL.Path)
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	_, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "bogus-id", info, logger)
	if err == nil {
		t.Fatalf("expected an error for a nonexistent project_id, got nil")
	}
	if !strings.Contains(err.Error(), "bogus-id") {
		t.Fatalf("expected error to mention the bad project_id, got: %v", err)
	}
}

func TestGetAllGroupsForUser_ProjectIDCheckSkippedWhenAbsent(t *testing.T) {
	var sawProjectsCall bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/v3/projects/"):
			sawProjectsCall = true
			w.WriteHeader(http.StatusOK)
			return
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
			_, _ = w.Write([]byte(`{"role_assignments": []}`))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	if _, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "", info, logger); err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}
	if sawProjectsCall {
		t.Fatalf("did not expect a /v3/projects call when project_id is absent")
	}
}

// rawGroupsHandler serves a fake Keystone where the user belongs to the given
// local groups, /v3/groups lists allGroups, and the user has no role
// assignments of their own.
func rawGroupsHandler(t *testing.T, localGroups, allGroups []keystoneGroup) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v3/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: allGroups})
		case strings.Contains(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: localGroups})
		case strings.HasSuffix(r.URL.Path, "/v3/role_assignments"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"role_assignments": []}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestNormalizeRole(t *testing.T) {
	tests := map[string]string{
		"_member_":          "member",
		"admin":             "admin",
		"tenant_admin":      "tenant_admin",
		"platform_admin":    "platform_admin",
		"default-dev-admin": "default.dev.admin",
	}
	for in, want := range tests {
		if got := normalizeRole(namedIdentifier{Name: in}); got != want {
			t.Errorf("normalizeRole(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGetAllGroupsForUser_LocalGroupCannotSpoofRoleGroup(t *testing.T) {
	// A domain admin creates a local group named exactly like the
	// system-scoped role3 role group and joins it.
	spoof := keystoneGroup{ID: "g1", Name: "cust-role3", DomainID: "dom-1"}
	ts := httptest.NewServer(rawGroupsHandler(t, []keystoneGroup{spoof}, []keystoneGroup{spoof}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := "keystone:dom-1/cust-role3"
	if len(groups) != 1 || groups[0] != want {
		t.Fatalf("unexpected groups: got %v, want [%q]", groups, want)
	}
}

func TestGetAllGroupsForUser_SSOGroupResolvedWithDomain(t *testing.T) {
	// Federated tokens may carry only the group ID; name and domain come
	// from /v3/groups. Group names may contain spaces and are kept verbatim.
	sso := keystoneGroup{ID: "g-sso", Name: "Platform Devs", DomainID: "dom-sso"}
	ts := httptest.NewServer(rawGroupsHandler(t, nil, []keystoneGroup{sso}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}
	info.User.OSFederation = &struct {
		Groups           []keystoneGroup `json:"groups"`
		IdentityProvider struct {
			ID string `json:"id"`
		} `json:"identity_provider"`
		Protocol struct {
			ID string `json:"id"`
		} `json:"protocol"`
	}{Groups: []keystoneGroup{{ID: "g-sso"}}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}

	want := "keystone:dom-sso/Platform Devs"
	if len(groups) != 1 || groups[0] != want {
		t.Fatalf("unexpected groups: got %v, want [%q]", groups, want)
	}
}

func TestGetAllGroupsForUser_SkipsGroupWithUnknownDomain(t *testing.T) {
	// Without a domain ID the group can't be namespaced, so it must be
	// dropped rather than emitted under an ambiguous name.
	noDomain := keystoneGroup{ID: "g1", Name: "devs"}
	ts := httptest.NewServer(rawGroupsHandler(t, []keystoneGroup{noDomain}, []keystoneGroup{noDomain}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(testDiscard{}, nil))
	info := &tokenInfo{User: userKeystone{ID: "u1", Name: "user1"}}

	groups, err := getAllGroupsForUser(t.Context(), ts.Client(), ts.URL, "tok", "cust", "", info, logger)
	if err != nil {
		t.Fatalf("getAllGroupsForUser error: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected no groups, got %v", groups)
	}
}

func TestHyphenatedRoleCannotSpoofProjectGroup(t *testing.T) {
	project := projectScope{
		Name:   "dev",
		Domain: namedIdentifier{Name: "default"},
	}
	projectGroup := generateGroupName(project, namedIdentifier{Name: "admin"}, "acme")

	systemGroup := generateSystemGroupName(namedIdentifier{Name: "default-dev-admin"}, "acme")
	if systemGroup == projectGroup {
		t.Fatalf("system role group %q collides with project group", systemGroup)
	}
	if want := "acme-default.dev.admin"; systemGroup != want {
		t.Fatalf("got %q, want %q", systemGroup, want)
	}

	domainGroup := generateDomainGroupName(namedIdentifier{Name: "default"}, namedIdentifier{Name: "dev-admin"}, "acme")
	if domainGroup == projectGroup {
		t.Fatalf("domain role group %q collides with project group", domainGroup)
	}

	idProject := projectScope{ID: "8f3a9b2c4d5e6f708192a3b4c5d6e7f8"}
	idGroup := generateProjectIDGroupName(idProject, namedIdentifier{Name: "admin"}, "acme")
	spoof := generateSystemGroupName(namedIdentifier{Name: "8f3a9b2c-admin"}, "acme")
	if spoof == idGroup {
		t.Fatalf("system role group %q collides with project ID group", spoof)
	}
}
