package keystonefed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// var _ connector.Login = (*Connector)(nil)
var _ connector.CallbackConnector = (*Connector)(nil)

type Connector struct {
	cfg    Config
	client *http.Client
	logger log.Logger

	// Stores callback information for the federation flow
	callbackURL string
	state       string
}

func New(cfg Config, logger log.Logger) (*Connector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Connector{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(30) * time.Second,
		},
		logger: logger,
	}, nil
}

// LoginURL returns the Keystone WebSSO URL or Federation SSO URL the browser should be sent to.
func (c *Connector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	c.logger.Infof("LoginURL called with callbackURL=%s, state=%s", callbackURL, state)
	ksBase := strings.TrimRight(c.cfg.BaseURL, "/")

	// Store the callback URL and state in the connector for use during callback handling
	c.callbackURL = callbackURL
	c.state = state
	c.logger.Infof("Stored callback URL=%s and state=%s in connector", callbackURL, state)

	// Use Shibboleth SSO login path for federation
	ssoLoginPath := c.cfg.ShibbolethLoginPath
	// Replace any {IdP} placeholder with the actual IdentityProviderID
	ssoLoginPath = strings.Replace(ssoLoginPath, "{IdP}", c.cfg.IdentityProviderID, -1)

	// Construct the Shibboleth login URL
	u, err := url.Parse(fmt.Sprintf("%s%s", ksBase, ssoLoginPath))
	if err != nil {
		return "", fmt.Errorf("parsing SSO login URL: %w", err)
	}

	// The target will be passed through the entire federation flow.
	// target is nothing but the relay state that will be used by shibboleth to redirect back to Dex.
	target := url.QueryEscape(fmt.Sprintf("%s&state=%s", callbackURL, state))
	q := u.Query()
	q.Set("target", target)
	c.logger.Infof("Setting target=%s for federation login", target)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// HandleCallback processes Keystone's redirect back to Dex.
func (c *Connector) HandleCallback(scopes connector.Scopes, r *http.Request) (connector.Identity, error) {
	c.logger.Infof("HandleCallback received request: URL=%s, Method=%s", r.URL.String(), r.Method)
	c.logger.Infof("Request headers: %v", r.Header)
	c.logger.Infof("Request cookies count: %d", len(r.Cookies()))
	for i, cookie := range r.Cookies() {
		c.logger.Infof("Cookie[%d]: Name=%s, Domain=%s", i, cookie.Name, cookie.Domain)
	}

	var ksToken string
	var err error
	var tokenInfo *tokenInfo
	identity := connector.Identity{}

	// Get state from query parameters
	state := r.URL.Query().Get("state")
	c.logger.Infof("State from query: %s", state)
	if state == "" {
		c.logger.Error("Missing state in request")
		return connector.Identity{}, fmt.Errorf("missing state")
	}
	// Extract federation cookies and use them to get a keystone token
	ksToken, err = c.getKeystoneTokenFromFederation(r)
	if err != nil {
		c.logger.Errorf("Error getting token from federation cookies: %v", err)
		return connector.Identity{}, fmt.Errorf("getting token from federation cookies: %w", err)
	}
	c.logger.Infof("Successfully obtained token from federation cookies")

	c.logger.Infof("Retrieving user info with token: %s", truncateToken(ksToken))
	tokenInfo, err = c.getTokenInfo(r.Context(), ksToken)
	if err != nil {
		return connector.Identity{}, err
	}
	if scopes.Groups {
		c.logger.Infof("groups scope requested, fetching groups")
		var err error
		adminToken, err := c.getAdminTokenUnscoped(r.Context())
		if err != nil {
			return identity, fmt.Errorf("keystone: failed to obtain admin token: %v", err)
		}
		identity.Groups, err = c.getGroups(r.Context(), adminToken, tokenInfo)
		if err != nil {
			return connector.Identity{}, err
		}
	}
	identity.Username = tokenInfo.User.Name
	identity.UserID = tokenInfo.User.ID

	user, err := c.getUser(r.Context(), tokenInfo.User.ID, ksToken)
	if err != nil {
		return identity, err
	}
	if user.User.Email != "" {
		identity.Email = user.User.Email
		identity.EmailVerified = true
	}

	data := connectorData{Token: ksToken}
	connData, err := json.Marshal(data)
	if err != nil {
		return identity, fmt.Errorf("marshal connector data: %v", err)
	}
	identity.ConnectorData = connData

	return identity, nil
}

func (c *Connector) getAdminTokenUnscoped(ctx context.Context) (string, error) {
	client := &http.Client{}
	domain := domainKeystone{
		Name: "default",
	}
	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods: []string{"password"},
				Password: password{
					User: user{
						Name:     c.cfg.AdminUsername,
						Domain:   domain,
						Password: c.cfg.AdminPassword,
					},
				},
			},
		},
	}
	jsonValue, err := json.Marshal(jsonData)
	if err != nil {
		return "", err
	}
	// https://developer.openstack.org/api-ref/identity/v3/#password-authentication-with-unscoped-authorization
	authTokenURL := c.cfg.BaseURL + "/keystone/v3/auth/tokens/"
	req, err := http.NewRequest("POST", authTokenURL, bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	resp, err := client.Do(req)

	if err != nil {
		return "", fmt.Errorf("keystone: error %v", err)
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("keystone login: error %v", resp.StatusCode)
	}
	if resp.StatusCode != 201 {
		return "", nil
	}
	return resp.Header.Get("X-Subject-Token"), nil
}

func (c *Connector) getAllGroups(ctx context.Context, token string) ([]keystoneGroup, error) {
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=list-groups-detail#list-groups
	groupsURL := c.cfg.BaseURL + "/keystone/v3/groups"
	req, err := http.NewRequest(http.MethodGet, groupsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorf("keystone: error while fetching groups\n")
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	groupsResp := new(groupsResponse)

	err = json.Unmarshal(data, &groupsResp)
	if err != nil {
		return nil, err
	}
	return groupsResp.Groups, nil
}

func (c *Connector) getUserGroups(ctx context.Context, userID string, token string) ([]keystoneGroup, error) {
	client := &http.Client{}
	// https://developer.openstack.org/api-ref/identity/v3/#list-groups-to-which-a-user-belongs
	groupsURL := c.cfg.BaseURL + "/keystone/v3/users/" + userID + "/groups"
	req, err := http.NewRequest("GET", groupsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		c.logger.Errorf("keystone: error while fetching user %q groups\n", userID)
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	groupsResp := new(groupsResponse)

	err = json.Unmarshal(data, &groupsResp)
	if err != nil {
		return nil, err
	}
	return groupsResp.Groups, nil
}

func (c *Connector) getRoleAssignments(ctx context.Context, token string, opts getRoleAssignmentsOptions) ([]roleAssignment, error) {
	endpoint := fmt.Sprintf("%s/v3/role_assignments?", c.cfg.BaseURL)
	// note: group and user filters are mutually exclusive
	if len(opts.userID) > 0 {
		endpoint = fmt.Sprintf("%seffective&user.id=%s", endpoint, opts.userID)
	} else if len(opts.groupID) > 0 {
		endpoint = fmt.Sprintf("%sgroup.id=%s", endpoint, opts.groupID)
	}

	// https://docs.openstack.org/api-ref/identity/v3/?expanded=validate-and-show-information-for-token-detail,list-role-assignments-detail#list-role-assignments
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorf("keystone: error while fetching role assignments: %v", err)
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	roleAssignmentResp := struct {
		RoleAssignments []roleAssignment `json:"role_assignments"`
	}{}

	err = json.Unmarshal(data, &roleAssignmentResp)
	if err != nil {
		return nil, err
	}

	return roleAssignmentResp.RoleAssignments, nil
}

func (c *Connector) getGroups(ctx context.Context, token string, tokenInfo *tokenInfo) ([]string, error) {
	var userGroups []string
	var userGroupIDs []string

	allGroups, err := c.getAllGroups(ctx, token)
	if err != nil {
		return nil, err
	}

	// For SSO users, groups are passed down through the federation API.
	if tokenInfo.User.OSFederation != nil {
		for _, osGroup := range tokenInfo.User.OSFederation.Groups {
			// If grouop name is empty, try to find the group by ID
			if len(osGroup.Name) == 0 {
				var ok bool
				osGroup, ok = findGroupByID(allGroups, osGroup.ID)
				if !ok {
					c.logger.Warnf("Group with ID '%s' attached to user '%s' could not be found. Skipping.",
						osGroup.ID, tokenInfo.User.ID)
					continue
				}
			}
			userGroups = append(userGroups, osGroup.Name)
			userGroupIDs = append(userGroupIDs, osGroup.ID)
		}
	}

	// For local users, fetch the groups stored in Keystone.
	localGroups, err := c.getUserGroups(ctx, tokenInfo.User.ID, token)
	if err != nil {
		return nil, err
	}

	for _, localGroup := range localGroups {
		// If group name is empty, try to find the group by ID
		if len(localGroup.Name) == 0 {
			var ok bool
			localGroup, ok = findGroupByID(allGroups, localGroup.ID)
			if !ok {
				c.logger.Warnf("Group with ID '%s' attached to user '%s' could not be found. Skipping.",
					localGroup.ID, tokenInfo.User.ID)
				continue
			}
		}
		userGroups = append(userGroups, localGroup.Name)
		userGroupIDs = append(userGroupIDs, localGroup.ID)
	}

	// Get user-related role assignments
	roleAssignments := []roleAssignment{}
	localUserRoleAssignments, err := c.getRoleAssignments(ctx, token, getRoleAssignmentsOptions{
		userID: tokenInfo.User.ID,
	})
	if err != nil {
		c.logger.Errorf("failed to fetch role assignments for userID %s: %s", tokenInfo.User.ID, err)
		return userGroups, err
	}
	roleAssignments = append(roleAssignments, localUserRoleAssignments...)

	// Get group-related role assignments
	for _, groupID := range userGroupIDs {
		groupRoleAssignments, err := c.getRoleAssignments(ctx, token, getRoleAssignmentsOptions{
			groupID: groupID,
		})
		if err != nil {
			c.logger.Errorf("failed to fetch role assignments for groupID %s: %s", groupID, err)
			return userGroups, err
		}
		roleAssignments = append(roleAssignments, groupRoleAssignments...)
	}

	if len(roleAssignments) == 0 {
		c.logger.Warnf("Warning: no role assignments found.")
		return userGroups, nil
	}

	roles, err := c.getRoles(ctx, token)
	if err != nil {
		return userGroups, err
	}
	roleMap := map[string]role{}
	for _, role := range roles {
		roleMap[role.ID] = role
	}

	projects, err := c.getProjects(ctx, token)
	if err != nil {
		return userGroups, err
	}
	projectMap := map[string]project{}
	for _, project := range projects {
		projectMap[project.ID] = project
	}

	//  Now create groups based on the role assignments
	var roleGroups []string

	// get the customer name to be prefixed in the group name
	customerName := c.cfg.CustomerName
	// if customerName is not provided in the keystone config get it from keystone host url.
	if customerName == "" {
		customerName, err = c.getHostname()
		if err != nil {
			return userGroups, err
		}
	}
	for _, roleAssignment := range roleAssignments {
		role, ok := roleMap[roleAssignment.Role.ID]
		if !ok {
			// Ignore role assignments to non-existent roles (shouldn't happen)
			continue
		}
		project, ok := projectMap[roleAssignment.Scope.Project.ID]
		if !ok {
			// Ignore role assignments to non-existent projects (shouldn't happen)
			continue
		}
		groupName := c.generateGroupName(project, role, customerName)
		roleGroups = append(roleGroups, groupName)
	}

	// combine user-groups and role-groups
	userGroups = append(userGroups, roleGroups...)
	return pruneDuplicates(userGroups), nil
}

func pruneDuplicates(ss []string) []string {
	set := map[string]struct{}{}
	var ns []string
	for _, s := range ss {
		if _, ok := set[s]; ok {
			continue
		}
		set[s] = struct{}{}
		ns = append(ns, s)
	}
	return ns
}

func (c *Connector) getRoles(ctx context.Context, token string) ([]role, error) {
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=validate-and-show-information-for-token-detail,list-role-assignments-detail,list-roles-detail#list-roles
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v3/roles", c.cfg.BaseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorf("keystone: error while fetching keystone roles\n")
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rolesResp := struct {
		Roles []role `json:"roles"`
	}{}

	err = json.Unmarshal(data, &rolesResp)
	if err != nil {
		return nil, err
	}

	return rolesResp.Roles, nil
}

func (c *Connector) getProjects(ctx context.Context, token string) ([]project, error) {
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=validate-and-show-information-for-token-detail,list-role-assignments-detail,list-roles-detail#list-roles
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v3/projects", c.cfg.BaseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorf("keystone: error while fetching keystone projects\n")
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	projectsResp := struct {
		Projects []project `json:"projects"`
	}{}

	err = json.Unmarshal(data, &projectsResp)
	if err != nil {
		return nil, err
	}

	return projectsResp.Projects, nil
}

func (c *Connector) getHostname() (string, error) {
	keystoneUrl := c.cfg.BaseURL
	parsedURL, err := url.Parse(keystoneUrl)
	if err != nil {
		return "", fmt.Errorf("error parsing URL: %v", err)
	}
	customerFqdn := parsedURL.Hostname()
	// get customer name and not the full fqdn
	parts := strings.Split(customerFqdn, ".")
	hostName := parts[0]

	return hostName, nil
}

func (c *Connector) generateGroupName(project project, role role, customerName string) string {
	roleName := role.Name
	if roleName == "_member_" {
		roleName = "member"
	}
	domainName := strings.ToLower(strings.ReplaceAll(c.cfg.DomainID, "_", "-"))
	projectName := strings.ToLower(strings.ReplaceAll(project.Name, "_", "-"))
	return customerName + "-" + domainName + "-" + projectName + "-" + roleName
}

func findGroupByID(groups []keystoneGroup, groupID string) (group keystoneGroup, ok bool) {
	for _, group := range groups {
		if group.ID == groupID {
			return group, true
		}
	}
	return group, false
}

func (c *Connector) getUser(ctx context.Context, userID string, token string) (*userResponse, error) {
	// https://developer.openstack.org/api-ref/identity/v3/#show-user-details
	userURL := c.cfg.BaseURL + "/keystone/v3/users/" + userID
	client := &http.Client{}
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	user := userResponse{}
	err = json.Unmarshal(data, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (c *Connector) getTokenInfo(ctx context.Context, token string) (*tokenInfo, error) {
	// https://developer.openstack.org/api-ref/identity/v3/#password-authentication-with-unscoped-authorization
	authTokenURL := c.cfg.BaseURL + "/keystone/v3/auth/tokens"
	c.logger.Infof("Fetching Keystone token info: %s", authTokenURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authTokenURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("X-Subject-Token", token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		c.logger.Errorf("keystone: get token info: error status code %d: %s\n", resp.StatusCode, strings.ReplaceAll(string(data), "\n", ""))
		return nil, fmt.Errorf("keystone: get token info: error status code %d", resp.StatusCode)
	}

	tokenResp := &tokenResponse{}
	err = json.Unmarshal(data, tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp.Token, nil
}

// getKeystoneTokenFromFederation gets a Keystone token using an existing federation session.
func (c *Connector) getKeystoneTokenFromFederation(r *http.Request) (string, error) {
	// Extract federation cookies from the request
	c.logger.Infof("Extracting federation cookies from request with %d cookies", len(r.Cookies()))
	var federationCookies []*http.Cookie
	for _, cookie := range r.Cookies() {
		c.logger.Infof("Examining cookie: Name=%s, Domain=%s, Path=%s", cookie.Name, cookie.Domain, cookie.Path)
		if strings.Contains(cookie.Name, "_shibsession_") ||
			strings.Contains(cookie.Name, "_saml_") ||
			strings.Contains(cookie.Name, "_openstack_") {
			c.logger.Infof("Found federation cookie: %s", cookie.Name)
			federationCookies = append(federationCookies, cookie)
		}
	}

	if len(federationCookies) == 0 {
		c.logger.Error("No federation cookies found in request")
		return "", fmt.Errorf("no federation cookies found in request")
	} else {
		c.logger.Infof("Found %d federation cookies in request", len(federationCookies))
	}

	// Use the federation cookies to get a token from Keystone
	return c.getKeystoneTokenWithFederationCookies(federationCookies)
}

// getKeystoneTokenWithFederationCookies makes a request to the OS-FEDERATION identity providers auth endpoint
// with the federation cookies to get a Keystone token.
func (c *Connector) getKeystoneTokenWithFederationCookies(cookies []*http.Cookie) (string, error) {
	c.logger.Infof("Getting Keystone token with %d federation cookies", len(cookies))
	ksBase := strings.TrimRight(c.cfg.BaseURL, "/")

	// Replace any {IdP} placeholder with the actual IdentityProviderID
	federationAuthPath := strings.Replace(c.cfg.FederationAuthPath, "{IdP}", c.cfg.IdentityProviderID, -1)
	c.logger.Infof("Using federation auth path: %s", federationAuthPath)

	// Create request to the federation auth endpoint
	federationAuthURL := fmt.Sprintf("%s%s", ksBase, federationAuthPath)
	c.logger.Infof("Requesting token from federation auth endpoint: %s", federationAuthURL)
	req, err := http.NewRequest("GET", federationAuthURL, nil)
	if err != nil {
		c.logger.Errorf("Error creating federation auth request: %v", err)
		return "", fmt.Errorf("creating federation auth request: %w", err)
	}

	// Add all federation cookies to the request
	for _, cookie := range cookies {
		c.logger.Infof("Adding federation cookie to request: %s", cookie.Name)
		req.AddCookie(cookie)
	}

	// Make the request to get a token
	c.logger.Info("Sending federation auth request...")
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorf("Error making federation auth request: %v", err)
		return "", fmt.Errorf("federation auth request: %w", err)
	}
	defer resp.Body.Close()
	c.logger.Infof("Federation auth response status: %s", resp.Status)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Errorf("Federation auth failed: %s body=%s", resp.Status, string(body))
		return "", fmt.Errorf("federation auth failed: %s body=%s", resp.Status, string(body))
	} else {
		c.logger.Info("Federation auth request succeeded")
	}

	// Extract the token from the X-Subject-Token header
	token := resp.Header.Get("X-Subject-Token")
	c.logger.Infof("X-Subject-Token header: %s", truncateToken(token))
	if token == "" {
		c.logger.Error("No X-Subject-Token header found in response")
		return "", fmt.Errorf("no X-Subject-Token in response")
	} else {
		c.logger.Info("Successfully obtained token from federation auth endpoint")
	}

	return token, nil
}

func truncateToken(token string) string {
	if len(token) > 50 {
		return token[:47] + "..."
	}
	return token
}
