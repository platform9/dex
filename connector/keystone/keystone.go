// Package keystone provides authentication strategy using Keystone.
package keystone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

type conn struct {
	Domain           string
	Host             string
	AdminUsername    string
	AdminPassword    string
	Groups           []group
	UseRolesAsGroups bool
	client           *http.Client
	Logger           log.Logger
}

type group struct {
	Name    string `json:"name"`
	Replace string `json:"replace"`
}

type userKeystone struct {
	Domain       domainKeystone `json:"domain"`
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	OSFederation *struct {
		Groups           []keystoneGroup `json:"groups"`
		IdentityProvider struct {
			ID string `json:"id"`
		} `json:"identity_provider"`
		Protocol struct {
			ID string `json:"id"`
		} `json:"protocol"`
	} `json:"OS-FEDERATION"`
}

type domainKeystone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Config holds the configuration parameters for Keystone connector.
// Keystone should expose API v3
// An example config:
//
//	connectors:
//		type: keystone
//		id: keystone
//		name: Keystone
//		config:
//			keystoneHost: http://example:5000
//			domain: default
//			keystoneUsername: demo
//			keystonePassword: DEMO_PASS
//			useRolesAsGroups: true
type Config struct {
	Domain           string  `json:"domain"`
	Host             string  `json:"keystoneHost"`
	AdminUsername    string  `json:"keystoneUsername"`
	AdminPassword    string  `json:"keystonePassword"`
	UseRolesAsGroups bool    `json:"useRolesAsGroups"`
	Groups           []group `json:"groups"`
}

type loginRequestData struct {
	auth `json:"auth"`
}

type auth struct {
	Identity identity `json:"identity"`
}

type identity struct {
	Methods  []string `json:"methods"`
	Password password `json:"password"`
}

type password struct {
	User user `json:"user"`
}

type user struct {
	Name     string `json:"name"`
	Domain   domain `json:"domain"`
	Password string `json:"password"`
}

type domain struct {
	ID string `json:"id"`
}

type tokenInfo struct {
	User  userKeystone `json:"user"`
	Roles []role       `json:"roles"`
}

type tokenResponse struct {
	Token tokenInfo `json:"token"`
}

type keystoneGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type groupsResponse struct {
	Groups []keystoneGroup `json:"groups"`
}

type userResponse struct {
	User struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		ID    string `json:"id"`
	} `json:"user"`
}

type role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DomainID    string `json:"domain_id"`
	Description string `json:"description"`
}

type identifierContainer struct {
	ID string `json:"id"`
}

type roleAssignment struct {
	User  identifierContainer `json:"user"`
	Group identifierContainer `json:"group"`
	Role  identifierContainer `json:"role"`
}

type connectorData struct {
	Token string `json:"token"`
}

var (
	_ connector.PasswordConnector = &conn{}
	_ connector.RefreshConnector  = &conn{}
)

// Open returns an authentication strategy using Keystone.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	return &conn{
		Domain:           c.Domain,
		Host:             c.Host,
		AdminUsername:    c.AdminUsername,
		AdminPassword:    c.AdminPassword,
		UseRolesAsGroups: c.UseRolesAsGroups,
		Groups:           c.Groups,
		Logger:           logger,
		client:           http.DefaultClient,
	}, nil
}

func (p *conn) Close() error { return nil }

func (p *conn) Login(ctx context.Context, scopes connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	var token string
	var tokenInfo *tokenInfo
	if username == "" || username == "_TOKEN_" {
		token = password
		tokenInfo, err = p.getTokenInfo(ctx, token)
		if err != nil {
			return connector.Identity{}, false, err
		}
	} else {
		token, tokenInfo, err = p.authenticate(ctx, username, password)
		if err != nil || tokenInfo == nil {
			return identity, false, err
		}
	}

	if p.groupsRequired(scopes.Groups) {
		var err error
		identity.Groups, err = p.getGroups(ctx, token, tokenInfo)
		if err != nil {
			return connector.Identity{}, false, err
		}
	}
	identity.Username = tokenInfo.User.Name
	identity.UserID = tokenInfo.User.ID

	user, err := p.getUser(ctx, tokenInfo.User.ID, token)
	if err != nil {
		return identity, false, err
	}
	if user.User.Email != "" {
		identity.Email = user.User.Email
		identity.EmailVerified = true
	}

	data := connectorData{Token: token}
	connData, err := json.Marshal(data)
	if err != nil {
		return identity, false, fmt.Errorf("marshal connector data: %v", err)
	}
	identity.ConnectorData = connData

	return identity, true, nil
}

func (p *conn) Prompt() string { return "username" }

func (p *conn) Refresh(
	ctx context.Context, scopes connector.Scopes, identity connector.Identity,
) (connector.Identity, error) {
	token, err := p.getAdminToken(ctx)
	if err != nil {
		return identity, fmt.Errorf("keystone: failed to obtain admin token: %v", err)
	}

	ok, err := p.checkIfUserExists(ctx, identity.UserID, token)
	if err != nil {
		return identity, err
	}
	if !ok {
		return identity, fmt.Errorf("keystone: user %q does not exist", identity.UserID)
	}

	tokenInfo := &tokenInfo{
		User: userKeystone{
			Name: identity.Username,
			ID:   identity.UserID,
		},
	}
	var data connectorData
	if err := json.Unmarshal(identity.ConnectorData, &data); err != nil {
		return identity, fmt.Errorf("keystone: unmarshal token info: %v", err)
	}
	// If there is a token associated with this refresh token, use that to look up
	// the token info. This can contain things like SSO groups which are not present elsewhere.
	if len(data.Token) > 0 {
		tokenInfo, err = p.getTokenInfo(ctx, data.Token)
		if err != nil {
			return identity, err
		}
	}

	if p.groupsRequired(scopes.Groups) {
		var err error
		identity.Groups, err = p.getGroups(ctx, token, tokenInfo)
		if err != nil {
			return identity, err
		}
	}
	return identity, nil
}

func (p *conn) authenticate(ctx context.Context, username, pass string) (string, *tokenInfo, error) {
	client := &http.Client{}
	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods: []string{"password"},
				Password: password{
					User: user{
						Name:     username,
						Domain:   domain{ID: p.Domain},
						Password: pass,
					},
				},
			},
		},
	}
	jsonValue, err := json.Marshal(jsonData)
	if err != nil {
		return "", nil, err
	}
	// https://developer.openstack.org/api-ref/identity/v3/#password-authentication-with-unscoped-authorization
	authTokenURL := p.Host + "/v3/auth/tokens/"
	req, err := http.NewRequest("POST", authTokenURL, bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	resp, err := client.Do(req)

	if err != nil {
		return "", nil, fmt.Errorf("keystone: error %v", err)
	}
	if resp.StatusCode/100 != 2 {
		return "", nil, fmt.Errorf("keystone login: error %v", resp.StatusCode)
	}
	if resp.StatusCode != 201 {
		return "", nil, nil
	}
	token := resp.Header.Get("X-Subject-Token")
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	tokenResp := &tokenResponse{}
	err = json.Unmarshal(data, tokenResp)
	if err != nil {
		return "", nil, fmt.Errorf("keystone: invalid token response: %v", err)
	}
	return token, &tokenResp.Token, nil
}

func (p *conn) getAdminToken(ctx context.Context) (string, error) {
	token, _, err := p.authenticate(ctx, p.AdminUsername, p.AdminPassword)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (p *conn) checkIfUserExists(ctx context.Context, userID string, token string) (bool, error) {
	user, err := p.getUser(ctx, userID, token)
	return user != nil, err
}

func (p *conn) getGroups(ctx context.Context, token string, tokenInfo *tokenInfo) ([]string, error) {
	var userGroups []string
	var userGroupIDs []string
	if tokenInfo.User.OSFederation != nil {
		// For SSO users, use the groups passed down through the federation API.
		for _, osGroup := range tokenInfo.User.OSFederation.Groups {
			if len(osGroup.Name) > 0 {
				userGroups = append(userGroups, osGroup.Name)
			}
			userGroupIDs = append(userGroupIDs, osGroup.ID)
		}
	} else {
		// For local users, fetch the groups stored in Keystone.
		localGroups, err := p.getUserGroups(ctx, tokenInfo.User.ID, token)
		if err != nil {
			return nil, err
		}
		for _, localGroup := range localGroups {
			if len(localGroup.Name) > 0 {
				userGroups = append(userGroups, localGroup.Name)
			}
			userGroupIDs = append(userGroupIDs, localGroup.ID)
		}
	}
	if p.UseRolesAsGroups {
		roleGroups, err := p.getUserRolesAsGroups(ctx, token, tokenInfo.User.ID, userGroupIDs, "")
		if err != nil {
			return nil, err
		}
		userGroups = append(userGroups, roleGroups...)
	}
	return p.filterGroups(pruneDuplicates(userGroups)), nil
}

func (p *conn) getUser(ctx context.Context, userID string, token string) (*userResponse, error) {
	// https://developer.openstack.org/api-ref/identity/v3/#show-user-details
	userURL := p.Host + "/v3/users/" + userID
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

func (p *conn) getTokenInfo(ctx context.Context, token string) (*tokenInfo, error) {
	// https://developer.openstack.org/api-ref/identity/v3/#password-authentication-with-unscoped-authorization
	authTokenURL := p.Host + "/v3/auth/tokens"
	p.Logger.Infof("Fetching Keystone token info: %s", authTokenURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authTokenURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("X-Subject-Token", token)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		p.Logger.Errorf("keystone: get token info: error status code %d: %s\n", resp.StatusCode, strings.ReplaceAll(string(data), "\n", ""))
		return nil, fmt.Errorf("keystone: get token info: error status code %d", resp.StatusCode)
	}

	tokenResp := &tokenResponse{}
	err = json.Unmarshal(data, tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp.Token, nil
}

func (p *conn) getUserGroups(ctx context.Context, userID string, token string) ([]keystoneGroup, error) {
	client := &http.Client{}
	// https://developer.openstack.org/api-ref/identity/v3/#list-groups-to-which-a-user-belongs
	groupsURL := p.Host + "/v3/users/" + userID + "/groups"
	req, err := http.NewRequest("GET", groupsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		p.Logger.Errorf("keystone: error while fetching user %q groups\n", userID)
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

func (p *conn) groupsRequired(groupScope bool) bool {
	return len(p.Groups) > 0 || groupScope
}

// If project ID is left empty, all roles will be fetched
func (p *conn) getUserRolesAsGroups(ctx context.Context, token string, userID string, groupIDs []string, projectID string) ([]string, error) {
	// Get user-related role assignments
	roleAssignments, err := p.getRoleAssignments(ctx, token, getRoleAssignmentsOptions{
		userID:    userID,
		projectID: projectID,
	})
	if err != nil {
		return nil, err
	}
	// Get group-related role assignments
	for _, groupID := range groupIDs {
		groupRoleAssignments, err := p.getRoleAssignments(ctx, token, getRoleAssignmentsOptions{
			groupID:   groupID,
			projectID: projectID,
		})
		if err != nil {
			return nil, err
		}
		roleAssignments = append(roleAssignments, groupRoleAssignments...)
	}

	roles, err := p.getRoles(ctx, token)
	if err != nil {
		return nil, err
	}
	roleMap := map[string]role{}
	for _, role := range roles {
		roleMap[role.ID] = role
	}
	var groups []string
	for _, roleAssignment := range roleAssignments {
		role, ok := roleMap[roleAssignment.Role.ID]
		if !ok {
			// Ignore role assignments to non-existent roles (shouldn't happen)
			continue
		}
		groups = append(groups, role.Name)
	}
	return groups, nil
}

type getRoleAssignmentsOptions struct {
	userID    string
	groupID   string
	projectID string
}

func (p *conn) getRoleAssignments(ctx context.Context, token string, opts getRoleAssignmentsOptions) ([]roleAssignment, error) {
	endpoint := fmt.Sprintf("%s/v3/role_assignments?&scope.project.id=%s", p.Host, opts.projectID)
	// note: group and user filters are mutually exclusive
	if len(opts.userID) > 0 {
		endpoint = fmt.Sprintf("%s&effective&user.id=%s", endpoint, opts.userID)
	} else if len(opts.groupID) > 0 {
		endpoint = fmt.Sprintf("%s&group.id=%s", endpoint, opts.groupID)
	}

	// https://docs.openstack.org/api-ref/identity/v3/?expanded=validate-and-show-information-for-token-detail,list-role-assignments-detail#list-role-assignments
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := p.client.Do(req)
	if err != nil {
		p.Logger.Errorf("keystone: error while fetching role assignments: %v", err)
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

func (p *conn) getRoles(ctx context.Context, token string) ([]role, error) {
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=validate-and-show-information-for-token-detail,list-role-assignments-detail,list-roles-detail#list-roles
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v3/roles", p.Host), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := p.client.Do(req)
	if err != nil {
		p.Logger.Errorf("keystone: error while fetching keystone roles\n")
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

func (p *conn) filterGroups(groups []string) []string {
	if len(p.Groups) == 0 {
		return groups
	}
	var matches []string
	for _, group := range groups {
		for _, filter := range p.Groups {
			// Future: support regexp?
			if group != filter.Name {
				continue
			}
			if len(filter.Replace) > 0 {
				group = filter.Replace
			}
			matches = append(matches, group)
		}
	}
	return matches
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
