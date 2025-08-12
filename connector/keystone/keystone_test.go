package keystone

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/dexidp/dex/connector"
)

const (
	invalidPass = "WRONG_PASS"

	testUser          = "test_user"
	testPass          = "test_pass"
	testEmail         = "test@example.com"
	testGroup         = "test_group"
	testDomainAltName = "altdomain"
	testDomainID      = "default"
	testDomainName    = "Default"
)

var (
	keystoneURL      = ""
	keystoneAdminURL = ""
	adminUser        = ""
	adminPass        = ""
	authTokenURL     = ""
	usersURL         = ""
	groupsURL        = ""
	domainsURL       = ""
)

type userReq struct {
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Enabled  bool     `json:"enabled"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
	DomainID string   `json:"domain_id,omitempty"`
}

type domainResponse struct {
	Domain domainKeystone `json:"domain"`
}

type domainsResponse struct {
	Domains []domainKeystone `json:"domains"`
}

type groupResponse struct {
	Group struct {
		ID string `json:"id"`
	} `json:"group"`
}

func getAdminToken(t *testing.T, adminName, adminPass string) (token, id string) {
	t.Helper()
	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods: []string{"password"},
				Password: password{
					User: user{
						Name:     adminName,
						Domain:   domainKeystone{ID: testDomainID},
						Password: adminPass,
					},
				},
			},
		},
	}

	body, err := json.Marshal(jsonData)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", authTokenURL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("keystone: failed to obtain admin token: %v\n", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	token = resp.Header.Get("X-Subject-Token")

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	tokenResp := new(tokenResponse)
	err = json.Unmarshal(data, &tokenResp)
	if err != nil {
		t.Fatal(err)
	}
	return token, tokenResp.Token.User.ID
}

func getOrCreateDomain(t *testing.T, token, domainName string) string {
	t.Helper()

	domainSearchURL := domainsURL + "?name=" + domainName
	reqGet, err := http.NewRequest("GET", domainSearchURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	reqGet.Header.Set("X-Auth-Token", token)
	reqGet.Header.Add("Content-Type", "application/json")
	respGet, err := http.DefaultClient.Do(reqGet)
	if err != nil {
		t.Fatal(err)
	}

	dataGet, err := io.ReadAll(respGet.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer respGet.Body.Close()

	domainsResp := new(domainsResponse)
	err = json.Unmarshal(dataGet, &domainsResp)
	if err != nil {
		t.Fatal(err)
	}

	if len(domainsResp.Domains) >= 1 {
		return domainsResp.Domains[0].ID
	}

	createDomainData := map[string]interface{}{
		"domain": map[string]interface{}{
			"name":    domainName,
			"enabled": true,
		},
	}

	body, err := json.Marshal(createDomainData)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", domainsURL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("failed to create domain %s", domainName)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	domainResp := new(domainResponse)
	err = json.Unmarshal(data, &domainResp)
	if err != nil {
		t.Fatal(err)
	}

	return domainResp.Domain.ID
}

func createUser(t *testing.T, token, domainID, userName, userEmail, userPass string) string {
	t.Helper()

	createUserData := map[string]interface{}{
		"user": userReq{
			DomainID: domainID,
			Name:     userName,
			Email:    userEmail,
			Enabled:  true,
			Password: userPass,
			Roles:    []string{"admin"},
		},
	}

	body, err := json.Marshal(createUserData)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", usersURL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	userResp := new(userResponse)
	err = json.Unmarshal(data, &userResp)
	if err != nil {
		t.Fatal(err)
	}

	return userResp.User.ID
}

// delete group or user
func deleteResource(t *testing.T, token, id, uri string) {
	t.Helper()

	deleteURI := uri + id
	req, err := http.NewRequest("DELETE", deleteURI, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	req.Header.Set("X-Auth-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	defer resp.Body.Close()
}

func createGroup(t *testing.T, token, description, name string) string {
	t.Helper()

	createGroupData := map[string]interface{}{
		"group": map[string]interface{}{
			"name":        name,
			"description": description,
		},
	}

	body, err := json.Marshal(createGroupData)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", groupsURL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	groupResp := new(groupResponse)
	err = json.Unmarshal(data, &groupResp)
	if err != nil {
		t.Fatal(err)
	}

	return groupResp.Group.ID
}

func addUserToGroup(t *testing.T, token, groupID, userID string) error {
	t.Helper()
	uri := groupsURL + groupID + "/users/" + userID
	req, err := http.NewRequest("PUT", uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	defer resp.Body.Close()

	return nil
}

func TestIncorrectCredentialsLogin(t *testing.T) {
	setupVariables(t)
	c := conn{
		client: http.DefaultClient,
		Host:   keystoneURL, Domain: domainKeystone{ID: testDomainID},
		AdminUsername: adminUser, AdminPassword: adminPass,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s := connector.Scopes{OfflineAccess: true, Groups: true}
	_, validPW, err := c.Login(context.Background(), s, adminUser, invalidPass)

	if validPW {
		t.Fatal("Incorrect password check")
	}

	if err == nil {
		t.Fatal("Error should be returned when invalid password is provided")
	}

	if !strings.Contains(err.Error(), "401") {
		t.Fatal("Unrecognized error, expecting 401")
	}
}

func TestValidUserLogin(t *testing.T) {
	setupVariables(t)
	token, _ := getAdminToken(t, adminUser, adminPass)

	type tUser struct {
		createDomain bool
		domain       domainKeystone
		username     string
		email        string
		password     string
	}

	type expect struct {
		username      string
		email         string
		verifiedEmail bool
	}

	tests := []struct {
		name     string
		input    tUser
		expected expect
	}{
		{
			name: "test with email address",
			input: tUser{
				createDomain: false,
				domain:       domainKeystone{ID: testDomainID},
				username:     testUser,
				email:        testEmail,
				password:     testPass,
			},
			expected: expect{
				username:      testUser,
				email:         testEmail,
				verifiedEmail: true,
			},
		},
		{
			name: "test without email address",
			input: tUser{
				createDomain: false,
				domain:       domainKeystone{ID: testDomainID},
				username:     testUser,
				email:        "",
				password:     testPass,
			},
			expected: expect{
				username:      testUser,
				email:         "",
				verifiedEmail: false,
			},
		},
		{
			name: "test with default domain Name",
			input: tUser{
				createDomain: false,
				domain:       domainKeystone{Name: testDomainName},
				username:     testUser,
				email:        testEmail,
				password:     testPass,
			},
			expected: expect{
				username:      testUser,
				email:         testEmail,
				verifiedEmail: true,
			},
		},
		{
			name: "test with custom domain Name",
			input: tUser{
				createDomain: true,
				domain:       domainKeystone{Name: testDomainAltName},
				username:     testUser,
				email:        testEmail,
				password:     testPass,
			},
			expected: expect{
				username:      testUser,
				email:         testEmail,
				verifiedEmail: true,
			},
		},
		{
			name: "test with custom domain ID",
			input: tUser{
				createDomain: true,
				domain:       domainKeystone{},
				username:     testUser,
				email:        testEmail,
				password:     testPass,
			},
			expected: expect{
				username:      testUser,
				email:         testEmail,
				verifiedEmail: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domainID := ""
			if tt.input.createDomain == true {
				domainID = getOrCreateDomain(t, token, testDomainAltName)
				t.Logf("getOrCreateDomain ID: %s\n", domainID)

				// if there was nothing set then use the dynamically generated domain ID
				if tt.input.domain.ID == "" && tt.input.domain.Name == "" {
					tt.input.domain.ID = domainID
				}
			}
			userID := createUser(t, token, domainID, tt.input.username, tt.input.email, tt.input.password)
			defer deleteResource(t, token, userID, usersURL)

			c := conn{
				client: http.DefaultClient,
				Host:   keystoneURL, Domain: tt.input.domain,
				AdminUsername: adminUser, AdminPassword: adminPass,
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			s := connector.Scopes{OfflineAccess: true, Groups: true}
			identity, validPW, err := c.Login(context.Background(), s, tt.input.username, tt.input.password)
			if err != nil {
				t.Fatalf("Login failed for user %s: %v", tt.input.username, err.Error())
			}
			t.Log(identity)
			if identity.Username != tt.expected.username {
				t.Fatalf("Invalid user. Got: %v. Wanted: %v", identity.Username, tt.expected.username)
			}
			if identity.UserID == "" {
				t.Fatalf("Didn't get any UserID back")
			}
			if identity.Email != tt.expected.email {
				t.Fatalf("Invalid email. Got: %v. Wanted: %v", identity.Email, tt.expected.email)
			}
			if identity.EmailVerified != tt.expected.verifiedEmail {
				t.Fatalf("Invalid verifiedEmail. Got: %v. Wanted: %v", identity.EmailVerified, tt.expected.verifiedEmail)
			}

			if !validPW {
				t.Fatal("Valid password was not accepted")
			}
		})
	}
}

func TestUseRefreshToken(t *testing.T) {
	setupVariables(t)
	token, adminID := getAdminToken(t, adminUser, adminPass)
	groupID := createGroup(t, token, "Test group description", testGroup)
	addUserToGroup(t, token, groupID, adminID)
	defer deleteResource(t, token, groupID, groupsURL)

	c := conn{
		client: http.DefaultClient,
		Host:   keystoneURL, Domain: domainKeystone{ID: testDomainID},
		AdminUsername: adminUser, AdminPassword: adminPass,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, err := c.Login(context.Background(), s, adminUser, adminPass)
	if err != nil {
		t.Fatal(err.Error())
	}

	identityRefresh, err := c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	expectEquals(t, 1, len(identityRefresh.Groups))
	expectEquals(t, testGroup, identityRefresh.Groups[0])
}

func TestUseRefreshTokenUserDeleted(t *testing.T) {
	setupVariables(t)
	token, _ := getAdminToken(t, adminUser, adminPass)
	userID := createUser(t, token, "", testUser, testEmail, testPass)

	c := conn{
		client: http.DefaultClient,
		Host:   keystoneURL, Domain: domainKeystone{ID: testDomainID},
		AdminUsername: adminUser, AdminPassword: adminPass,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, err := c.Login(context.Background(), s, testUser, testPass)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, err = c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	deleteResource(t, token, userID, usersURL)
	_, err = c.Refresh(context.Background(), s, identityLogin)

	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestUseRefreshTokenGroupsChanged(t *testing.T) {
	setupVariables(t)
	token, _ := getAdminToken(t, adminUser, adminPass)
	userID := createUser(t, token, "", testUser, testEmail, testPass)
	defer deleteResource(t, token, userID, usersURL)

	c := conn{
		client: http.DefaultClient,
		Host:   keystoneURL, Domain: domainKeystone{ID: testDomainID},
		AdminUsername: adminUser, AdminPassword: adminPass,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, err := c.Login(context.Background(), s, testUser, testPass)
	if err != nil {
		t.Fatal(err.Error())
	}

	identityRefresh, err := c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	expectEquals(t, 0, len(identityRefresh.Groups))

	groupID := createGroup(t, token, "Test group", testGroup)
	addUserToGroup(t, token, groupID, userID)
	defer deleteResource(t, token, groupID, groupsURL)

	identityRefresh, err = c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	expectEquals(t, 1, len(identityRefresh.Groups))
}

func TestNoGroupsInScope(t *testing.T) {
	setupVariables(t)
	token, _ := getAdminToken(t, adminUser, adminPass)
	userID := createUser(t, token, "", testUser, testEmail, testPass)
	defer deleteResource(t, token, userID, usersURL)

	c := conn{
		client: http.DefaultClient,
		Host:   keystoneURL, Domain: domainKeystone{ID: testDomainID},
		AdminUsername: adminUser, AdminPassword: adminPass,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s := connector.Scopes{OfflineAccess: true, Groups: false}

	groupID := createGroup(t, token, "Test group", testGroup)
	addUserToGroup(t, token, groupID, userID)
	defer deleteResource(t, token, groupID, groupsURL)

	identityLogin, _, err := c.Login(context.Background(), s, testUser, testPass)
	if err != nil {
		t.Fatal(err.Error())
	}
	expectEquals(t, 0, len(identityLogin.Groups))

	identityRefresh, err := c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}
	expectEquals(t, 0, len(identityRefresh.Groups))
}

func setupVariables(t *testing.T) {
	keystoneURLEnv := "DEX_KEYSTONE_URL"
	keystoneAdminURLEnv := "DEX_KEYSTONE_ADMIN_URL"
	keystoneAdminUserEnv := "DEX_KEYSTONE_ADMIN_USER"
	keystoneAdminPassEnv := "DEX_KEYSTONE_ADMIN_PASS"
	keystoneURL = os.Getenv(keystoneURLEnv)
	if keystoneURL == "" {
		t.Skipf("variable %q not set, skipping keystone connector tests\n", keystoneURLEnv)
		return
	}
	keystoneAdminURL = os.Getenv(keystoneAdminURLEnv)
	if keystoneAdminURL == "" {
		t.Skipf("variable %q not set, skipping keystone connector tests\n", keystoneAdminURLEnv)
		return
	}
	adminUser = os.Getenv(keystoneAdminUserEnv)
	if adminUser == "" {
		t.Skipf("variable %q not set, skipping keystone connector tests\n", keystoneAdminUserEnv)
		return
	}
	adminPass = os.Getenv(keystoneAdminPassEnv)
	if adminPass == "" {
		t.Skipf("variable %q not set, skipping keystone connector tests\n", keystoneAdminPassEnv)
		return
	}
	authTokenURL = keystoneURL + "/v3/auth/tokens/"
	usersURL = keystoneAdminURL + "/v3/users/"
	groupsURL = keystoneAdminURL + "/v3/groups/"
	domainsURL = keystoneAdminURL + "/v3/domains/"
}

func expectEquals(t *testing.T, a interface{}, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Expected %v to be equal %v", a, b)
	}
}

func newNoopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestAuthenticate_TokenMode(t *testing.T) {
	// Test Login with token mode (username="_TOKEN_")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v3/auth/tokens" {
			_ = json.NewEncoder(w).Encode(tokenResponse{Token: tokenInfo{User: userKeystone{ID: "u1", Name: "tokenuser"}}})
		} else if strings.HasPrefix(r.URL.Path, "/v3/users/") {
			_ = json.NewEncoder(w).Encode(userResponse{User: struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				ID    string `json:"id"`
			}{Name: "tokenuser", Email: "tokenuser@example.com", ID: "u1"}})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := &conn{Host: ts.URL, client: ts.Client(), Logger: newNoopLogger()}

	// Test token mode login
	identity, valid, err := c.Login(context.Background(), connector.Scopes{}, "_TOKEN_", "some-token")
	if err != nil {
		t.Fatalf("Login with token failed: %v", err)
	}
	if !valid {
		t.Error("Expected token login to be valid")
	}
	if identity.Username != "tokenuser" {
		t.Errorf("Expected username tokenuser, got %s", identity.Username)
	}
	if identity.Email != "tokenuser@example.com" {
		t.Errorf("Expected email tokenuser@example.com, got %s", identity.Email)
	}
	if !identity.EmailVerified {
		t.Error("Expected email to be verified")
	}
}

func TestGetHostname(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
		wantErr  bool
	}{
		{"standard https", "https://customer1.example.com:5000", "customer1", false},
		{"http with port", "http://test-host.domain.com:8080", "test-host", false},
		{"no port", "https://myhost.example.org", "myhost", false},
		{"ip address", "http://192.168.1.100:5000", "192", false},
		{"localhost", "http://localhost:5000", "localhost", false},
		{"invalid url", "://invalid-url", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &conn{Host: tt.host, Logger: newNoopLogger()}
			got, err := c.getHostname()
			if (err != nil) != tt.wantErr {
				t.Errorf("getHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("getHostname() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenerateGroupName(t *testing.T) {
	c := &conn{Domain: domainKeystone{Name: "Default_Domain"}, Logger: newNoopLogger()}
	proj := project{ID: "p1", Name: "My_Project"}
	roleMember := role{ID: "r1", Name: "_member_"}
	roleAdmin := role{ID: "r2", Name: "admin"}
	name1 := c.generateGroupName(proj, roleMember, "cust")
	name2 := c.generateGroupName(proj, roleAdmin, "cust")
	if name1 != "cust-default-domain-my-project-member" {
		t.Fatalf("member name unexpected: %s", name1)
	}
	if name2 != "cust-default-domain-my-project-admin" {
		t.Fatalf("admin name unexpected: %s", name2)
	}

	// Test edge cases
	projSpecial := project{ID: "p2", Name: "Special_Project_Name"}
	roleSpecial := role{ID: "r3", Name: "custom_role"}
	name3 := c.generateGroupName(projSpecial, roleSpecial, "customer-name")
	expected := "customer-name-default-domain-special-project-name-custom_role"
	if name3 != expected {
		t.Fatalf("special name unexpected: got %s, want %s", name3, expected)
	}
}

func TestPruneDuplicates(t *testing.T) {
	in := []string{"a", "b", "a", "c", "b"}
	out := pruneDuplicates(in)
	expectEquals(t, []string{"a", "b", "c"}, out)
}

func TestFindGroupByID(t *testing.T) {
	groups := []keystoneGroup{{ID: "1", Name: "g1"}, {ID: "2", Name: "g2"}, {ID: "3", Name: ""}}
	
	// Test finding existing group
	g, ok := findGroupByID(groups, "2")
	if !ok || g.Name != "g2" {
		t.Fatalf("expected to find g2, got %+v ok=%v", g, ok)
	}
	
	// Test finding group with empty name
	g, ok = findGroupByID(groups, "3")
	if !ok || g.ID != "3" {
		t.Fatalf("expected to find group with ID 3, got %+v ok=%v", g, ok)
	}
	
	// Test not finding non-existent group
	_, ok = findGroupByID(groups, "999")
	if ok {
		t.Fatalf("did not expect to find id 999")
	}
	
	// Test empty groups slice
	_, ok = findGroupByID([]keystoneGroup{}, "1")
	if ok {
		t.Fatalf("did not expect to find anything in empty slice")
	}
}

func TestHTTPHelpers(t *testing.T) {
	// Mock Keystone API endpoints used by helpers
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/groups":
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{{ID: "g1", Name: "Group1"}, {ID: "g2", Name: "Group2"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{{ID: "g1", Name: "Group1"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/roles":
			_ = json.NewEncoder(w).Encode(struct{ Roles []role `json:"roles"` }{Roles: []role{{ID: "r1", Name: "admin"}, {ID: "r2", Name: "_member_"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/projects":
			_ = json.NewEncoder(w).Encode(struct{ Projects []project `json:"projects"` }{Projects: []project{{ID: "p1", Name: "Project1", DomainID: "default"}, {ID: "p2", Name: "Project2", DomainID: "default"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v3/users/") && !strings.HasSuffix(r.URL.Path, "/groups"):
			_ = json.NewEncoder(w).Encode(userResponse{User: struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				ID    string `json:"id"`
			}{Name: "u1", Email: "u1@example.com", ID: "u1"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/auth/tokens":
			_ = json.NewEncoder(w).Encode(tokenResponse{Token: tokenInfo{User: userKeystone{ID: "u1", Name: "u1"}}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "user.id="):
			// User role assignments
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{{
				Scope: projectScope{Project: identifierContainer{ID: "p1"}},
				User:  identifierContainer{ID: "u1"},
				Role:  identifierContainer{ID: "r1"},
			}}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "group.id="):
			// Group role assignments
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{{
				Scope: projectScope{Project: identifierContainer{ID: "p2"}},
				Role:  identifierContainer{ID: "r2"},
			}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := &conn{Host: ts.URL, client: ts.Client(), Logger: newNoopLogger(), Domain: domainKeystone{Name: "Default"}}
	ctx := context.Background()

	// Test getAllGroups
	groups, err := c.getAllGroups(ctx, "token")
	if err != nil || len(groups) != 2 || groups[0].Name != "Group1" {
		t.Fatalf("getAllGroups unexpected: groups=%+v err=%v", groups, err)
	}

	// Test getUserGroups
	ug, err := c.getUserGroups(ctx, "u1", "token")
	if err != nil || len(ug) != 1 || ug[0].ID != "g1" {
		t.Fatalf("getUserGroups unexpected: groups=%+v err=%v", ug, err)
	}

	// Test getRoles
	roles, err := c.getRoles(ctx, "token")
	if err != nil || len(roles) != 2 || roles[0].ID != "r1" {
		t.Fatalf("getRoles unexpected: roles=%+v err=%v", roles, err)
	}

	// Test getProjects
	projects, err := c.getProjects(ctx, "token")
	if err != nil || len(projects) != 2 || projects[0].ID != "p1" {
		t.Fatalf("getProjects unexpected: projects=%+v err=%v", projects, err)
	}

	// Test getUser
	usr, err := c.getUser(ctx, "u1", "token")
	if err != nil || usr == nil || usr.User.Email != "u1@example.com" {
		t.Fatalf("getUser unexpected: user=%+v err=%v", usr, err)
	}

	// Test getTokenInfo
	ti, err := c.getTokenInfo(ctx, "token")
	if err != nil || ti == nil || ti.User.ID != "u1" {
		t.Fatalf("getTokenInfo unexpected: ti=%+v err=%v", ti, err)
	}

	// Test getRoleAssignments for user
	ras, err := c.getRoleAssignments(ctx, "token", getRoleAssignmentsOptions{userID: "u1"})
	if err != nil || len(ras) != 1 || ras[0].Role.ID != "r1" {
		t.Fatalf("getRoleAssignments for user unexpected: ras=%+v err=%v", ras, err)
	}

	// Test getRoleAssignments for group
	gras, err := c.getRoleAssignments(ctx, "token", getRoleAssignmentsOptions{groupID: "g1"})
	if err != nil || len(gras) != 1 || gras[0].Role.ID != "r2" {
		t.Fatalf("getRoleAssignments for group unexpected: gras=%+v err=%v", gras, err)
	}
}

func TestGetGroups_ComposesUserLocalAndRoleGroups(t *testing.T) {
	// Mock comprehensive Keystone endpoints for getGroups testing
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/groups":
			// Return all groups including one with empty name for ID resolution
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{
				{ID: "g1", Name: "LocalGroup1"},
				{ID: "g2", Name: "ResolvedGroup2"},
				{ID: "g3", Name: "SSOGroup3"},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/roles":
			_ = json.NewEncoder(w).Encode(struct{ Roles []role `json:"roles"` }{Roles: []role{
				{ID: "r1", Name: "admin"},
				{ID: "r2", Name: "_member_"},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/projects":
			_ = json.NewEncoder(w).Encode(struct{ Projects []project `json:"projects"` }{Projects: []project{
				{ID: "p1", Name: "Project_One"},
				{ID: "p2", Name: "Project_Two"},
			}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			// Local groups for user including one with empty name
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{
				{ID: "g1", Name: "LocalGroup1"},
				{ID: "g2", Name: ""}, // Empty name, should be resolved via findGroupByID
			}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "user.id="):
			// User role assignments
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{
				{
					Scope: projectScope{Project: identifierContainer{ID: "p1"}},
					User:  identifierContainer{ID: "u1"},
					Role:  identifierContainer{ID: "r1"},
				},
			}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "group.id=g1"):
			// Group role assignments for g1
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{
				{
					Scope: projectScope{Project: identifierContainer{ID: "p2"}},
					Role:  identifierContainer{ID: "r2"},
				},
			}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "group.id=g2"):
			// Group role assignments for g2
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "group.id=g3"):
			// Group role assignments for g3 (SSO group)
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := &conn{
		Host: ts.URL,
		client: ts.Client(),
		Logger: newNoopLogger(),
		Domain: domainKeystone{Name: "Test_Domain"},
		CustomerName: "testcust",
	}
	ctx := context.Background()

	// Create tokenInfo with SSO federation groups (one named, one by ID only)
	ti := &tokenInfo{User: userKeystone{
		ID:   "u1",
		Name: "testuser",
		OSFederation: &struct {
			Groups           []keystoneGroup `json:"groups"`
			IdentityProvider struct{ ID string `json:"id"` } `json:"identity_provider"`
			Protocol         struct{ ID string `json:"id"` } `json:"protocol"`
		}{Groups: []keystoneGroup{
			{ID: "g3", Name: "SSOGroup3"}, // Named SSO group
			{ID: "g1", Name: ""},         // SSO group by ID only, should be resolved
		}},
	}}

	groups, err := c.getGroups(ctx, "token", ti)
	if err != nil {
		t.Fatalf("getGroups error: %v", err)
	}

	// Expected groups:
	// 1. SSO groups: "SSOGroup3", "LocalGroup1" (resolved from ID)
	// 2. Local groups: "LocalGroup1", "ResolvedGroup2" (resolved from empty name)
	// 3. Role-derived groups: "testcust-test-domain-project-one-admin", "testcust-test-domain-project-two-member"
	expectedGroups := map[string]bool{
		"SSOGroup3":     false, // From SSO federation
		"LocalGroup1":   false, // From both SSO (resolved) and local groups
		"ResolvedGroup2": false, // From local groups (resolved from empty name)
		"testcust-test-domain-project-one-admin":   false, // From user role assignment
		"testcust-test-domain-project-two-member":  false, // From group role assignment
	}

	for _, group := range groups {
		if _, exists := expectedGroups[group]; exists {
			expectedGroups[group] = true
		}
	}

	// Verify all expected groups were found
	for groupName, found := range expectedGroups {
		if !found {
			t.Errorf("Expected group %s not found in result: %v", groupName, groups)
		}
	}

	// Verify no duplicates (LocalGroup1 appears in both SSO and local, should be deduped)
	localGroup1Count := 0
	for _, group := range groups {
		if group == "LocalGroup1" {
			localGroup1Count++
		}
	}
	if localGroup1Count != 1 {
		t.Errorf("Expected LocalGroup1 to appear exactly once (deduped), but found %d times", localGroup1Count)
	}
}

func TestGetGroups_NoSSO_OnlyLocalAndRoles(t *testing.T) {
	// Test getGroups for non-SSO user (no OSFederation)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/groups":
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{{ID: "g1", Name: "LocalGroup1"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/roles":
			_ = json.NewEncoder(w).Encode(struct{ Roles []role `json:"roles"` }{Roles: []role{{ID: "r1", Name: "admin"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/projects":
			_ = json.NewEncoder(w).Encode(struct{ Projects []project `json:"projects"` }{Projects: []project{{ID: "p1", Name: "TestProject"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{{ID: "g1", Name: "LocalGroup1"}}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "user.id="):
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{{
				Scope: projectScope{Project: identifierContainer{ID: "p1"}},
				User:  identifierContainer{ID: "u1"},
				Role:  identifierContainer{ID: "r1"},
			}}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "group.id="):
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := &conn{
		Host: ts.URL,
		client: ts.Client(),
		Logger: newNoopLogger(),
		Domain: domainKeystone{Name: "Default"},
		CustomerName: "testcust",
	}
	ctx := context.Background()

	// Non-SSO user (no OSFederation)
	ti := &tokenInfo{User: userKeystone{ID: "u1", Name: "testuser", OSFederation: nil}}

	groups, err := c.getGroups(ctx, "token", ti)
	if err != nil {
		t.Fatalf("getGroups error: %v", err)
	}

	// Expected: local group + role-derived group
	expected := []string{"LocalGroup1", "testcust-default-testproject-admin"}
	if len(groups) != len(expected) {
		t.Fatalf("Expected %d groups, got %d: %v", len(expected), len(groups), groups)
	}

	for _, exp := range expected {
		found := false
		for _, actual := range groups {
			if actual == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected group %s not found in %v", exp, groups)
		}
	}
}

func TestGetGroups_CustomerNameFallback(t *testing.T) {
	// Test getGroups when CustomerName is empty, should use getHostname()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/groups":
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/roles":
			_ = json.NewEncoder(w).Encode(struct{ Roles []role `json:"roles"` }{Roles: []role{{ID: "r1", Name: "admin"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v3/projects":
			_ = json.NewEncoder(w).Encode(struct{ Projects []project `json:"projects"` }{Projects: []project{{ID: "p1", Name: "TestProject"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v3/users/") && strings.HasSuffix(r.URL.Path, "/groups"):
			_ = json.NewEncoder(w).Encode(groupsResponse{Groups: []keystoneGroup{}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "user.id="):
			_ = json.NewEncoder(w).Encode(struct{ RoleAssignments []roleAssignment `json:"role_assignments"` }{RoleAssignments: []roleAssignment{{
				Scope: projectScope{Project: identifierContainer{ID: "p1"}},
				User:  identifierContainer{ID: "u1"},
				Role:  identifierContainer{ID: "r1"},
			}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := &conn{
		Host: ts.URL, // Use the test server URL directly
		client: ts.Client(),
		Logger: newNoopLogger(),
		Domain: domainKeystone{Name: "Default"},
		CustomerName: "", // Empty, should fallback to getHostname()
	}
	ctx := context.Background()

	ti := &tokenInfo{User: userKeystone{ID: "u1", Name: "testuser", OSFederation: nil}}

	groups, err := c.getGroups(ctx, "token", ti)
	if err != nil {
		t.Fatalf("getGroups error: %v", err)
	}

	// Should use hostname from ts.URL (e.g., "127" from "127.0.0.1")
	if len(groups) == 0 {
		t.Fatal("Expected at least one role-derived group")
	}

	// Verify the group name contains the hostname prefix
	found := false
	for _, group := range groups {
		if strings.Contains(group, "127") && strings.Contains(group, "default-testproject-admin") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected group with hostname prefix, got: %v", groups)
	}
}

func TestCheckIfUserExists(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/users/existing") {
			_ = json.NewEncoder(w).Encode(userResponse{User: struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				ID    string `json:"id"`
			}{Name: "existing", Email: "existing@example.com", ID: "existing"}})
		} else if strings.HasSuffix(r.URL.Path, "/users/nonexistent") {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := &conn{Host: ts.URL, client: ts.Client(), Logger: newNoopLogger()}
	ctx := context.Background()

	// Test existing user
	exists, err := c.checkIfUserExists(ctx, "existing", "token")
	if err != nil {
		t.Fatalf("checkIfUserExists error for existing user: %v", err)
	}
	if !exists {
		t.Error("Expected existing user to exist")
	}

	// Test non-existent user
	exists, err = c.checkIfUserExists(ctx, "nonexistent", "token")
	if err != nil {
		t.Fatalf("checkIfUserExists error for non-existent user: %v", err)
	}
	if exists {
		t.Error("Expected non-existent user to not exist")
	}
}
