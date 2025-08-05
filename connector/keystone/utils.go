package keystone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dexidp/dex/pkg/log"
)

// Shared utility functions for both keystone and keystonefed connectors

func getAdminTokenUnscoped(ctx context.Context, client *http.Client, baseURL, adminUsername, adminPassword string) (string, error) {
	domain := domainKeystone{
		Name: "default",
	}
	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods: []string{"password"},
				Password: password{
					User: user{
						Name:     adminUsername,
						Domain:   domain,
						Password: adminPassword,
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
	authTokenURL := baseURL + "/keystone/v3/auth/tokens/"
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

// getAllKeystoneGroups returns all groups in keystone
func getAllKeystoneGroups(ctx context.Context, client *http.Client, baseURL, token string) ([]keystoneGroup, error) {
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=list-groups-detail#list-groups
	groupsURL := baseURL + "/keystone/v3/groups"
	req, err := http.NewRequest(http.MethodGet, groupsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
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

// getUserLocalGroups returns local groups for a user
func getUserLocalGroups(ctx context.Context, client *http.Client, baseURL, userID, token string) ([]keystoneGroup, error) {
	// https://developer.openstack.org/api-ref/identity/v3/#list-groups-to-which-a-user-belongs
	groupsURL := baseURL + "/keystone/v3/users/" + userID + "/groups"
	req, err := http.NewRequest("GET", groupsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
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

// getRoleAssignments returns role assignments for a user or group
func getRoleAssignments(ctx context.Context, client *http.Client, baseURL, token string, opts getRoleAssignmentsOptions, logger log.Logger) ([]roleAssignment, error) {
	endpoint := fmt.Sprintf("%s/keystone/v3/role_assignments?", baseURL)
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
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("keystone: error while fetching role assignments: %v", err)
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

// getRoles returns all roles in keystone
func getRoles(ctx context.Context, client *http.Client, baseURL, token string, logger log.Logger) ([]role, error) {
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=validate-and-show-information-for-token-detail,list-role-assignments-detail,list-roles-detail#list-roles
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/keystone/v3/roles", baseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("keystone: error while fetching keystone roles\n")
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

// getProjects returns all projects in keystone
func getProjects(ctx context.Context, client *http.Client, baseURL, token string, logger log.Logger) ([]project, error) {
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=validate-and-show-information-for-token-detail,list-role-assignments-detail,list-roles-detail#list-roles
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/keystone/v3/projects", baseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("keystone: error while fetching keystone projects\n")
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

// getHostname returns the hostname from the base URL
func getHostname(baseURL string) (string, error) {
	keystoneUrl := baseURL
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

// generateGroupName generates a group name based on project, role, customer name, and domain ID
func generateGroupName(project project, role role, customerName, domainID string) string {
	roleName := role.Name
	if roleName == "_member_" {
		roleName = "member"
	}
	domainName := strings.ToLower(strings.ReplaceAll(domainID, "_", "-"))
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

func getUser(ctx context.Context, client *http.Client, baseURL, userID, token string) (*userResponse, error) {
	// https://developer.openstack.org/api-ref/identity/v3/#show-user-details
	userURL := baseURL + "/keystone/v3/users/" + userID
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

func getTokenInfo(ctx context.Context, client *http.Client, baseURL, token string, logger log.Logger) (*tokenInfo, error) {
	// https://developer.openstack.org/api-ref/identity/v3/#password-authentication-with-unscoped-authorization
	authTokenURL := baseURL + "/keystone/v3/auth/tokens"
	logger.Debugf("Fetching Keystone token info: %s", authTokenURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authTokenURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("X-Subject-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logger.Errorf("keystone: get token info: error status code %d: %s\n", resp.StatusCode, strings.ReplaceAll(string(data), "\n", ""))
		return nil, fmt.Errorf("keystone: get token info: error status code %d", resp.StatusCode)
	}

	tokenResp := &tokenResponse{}
	err = json.Unmarshal(data, tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp.Token, nil
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

// getAllGroupsForUser returns all groups for a user (local groups + SSO groups + role groups)
func getAllGroupsForUser(ctx context.Context, client *http.Client, baseURL, token, customerName, domainID string, tokenInfo *tokenInfo, logger log.Logger) ([]string, error) {
	var userGroups []string
	var userGroupIDs []string

	allGroups, err := getAllKeystoneGroups(ctx, client, baseURL, token)
	if err != nil {
		return nil, err
	}

	// 1. Get SSO groups
	// For SSO users, groups are passed down through the federation API.
	if tokenInfo.User.OSFederation != nil {
		for _, osGroup := range tokenInfo.User.OSFederation.Groups {
			// If group name is empty, try to find the group by ID
			if len(osGroup.Name) == 0 {
				var ok bool
				osGroup, ok = findGroupByID(allGroups, osGroup.ID)
				if !ok {
					logger.Warnf("Group with ID '%s' attached to user '%s' could not be found. Skipping.",
						osGroup.ID, tokenInfo.User.ID)
					continue
				}
			}
			userGroups = append(userGroups, osGroup.Name)
			userGroupIDs = append(userGroupIDs, osGroup.ID)
		}
	}

	// 2. Get local groups
	// For local users, fetch the groups stored in Keystone.
	localGroups, err := getUserLocalGroups(ctx, client, baseURL, tokenInfo.User.ID, token)
	if err != nil {
		return nil, err
	}

	for _, localGroup := range localGroups {
		// If group name is empty, try to find the group by ID
		if len(localGroup.Name) == 0 {
			var ok bool
			localGroup, ok = findGroupByID(allGroups, localGroup.ID)
			if !ok {
				logger.Warnf("Group with ID '%s' attached to user '%s' could not be found. Skipping.",
					localGroup.ID, tokenInfo.User.ID)
				continue
			}
		}
		userGroups = append(userGroups, localGroup.Name)
		userGroupIDs = append(userGroupIDs, localGroup.ID)
	}

	// Get user-related role assignments
	roleAssignments := []roleAssignment{}
	localUserRoleAssignments, err := getRoleAssignments(ctx, client, baseURL, token, getRoleAssignmentsOptions{
		userID: tokenInfo.User.ID,
	}, logger)
	if err != nil {
		logger.Errorf("failed to fetch role assignments for userID %s: %s", tokenInfo.User.ID, err)
		return userGroups, err
	}
	roleAssignments = append(roleAssignments, localUserRoleAssignments...)

	// Get group-related role assignments
	for _, groupID := range userGroupIDs {
		groupRoleAssignments, err := getRoleAssignments(ctx, client, baseURL, token, getRoleAssignmentsOptions{
			groupID: groupID,
		}, logger)
		if err != nil {
			logger.Errorf("failed to fetch role assignments for groupID %s: %s", groupID, err)
			return userGroups, err
		}
		roleAssignments = append(roleAssignments, groupRoleAssignments...)
	}

	if len(roleAssignments) == 0 {
		logger.Warnf("Warning: no role assignments found.")
		return userGroups, nil
	}

	roles, err := getRoles(ctx, client, baseURL, token, logger)
	if err != nil {
		return userGroups, err
	}
	roleMap := map[string]role{}
	for _, role := range roles {
		roleMap[role.ID] = role
	}

	projects, err := getProjects(ctx, client, baseURL, token, logger)
	if err != nil {
		return userGroups, err
	}
	projectMap := map[string]project{}
	for _, project := range projects {
		projectMap[project.ID] = project
	}

	// 3. Now create groups based on the role assignments
	var roleGroups []string

	// get the customer name to be prefixed in the group name
	// if customerName is not provided in the keystone config get it from keystone host url.
	if customerName == "" {
		customerName, err = getHostname(baseURL)
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
		groupName := generateGroupName(project, role, customerName, domainID)
		roleGroups = append(roleGroups, groupName)
	}

	// combine local groups + sso groups + role groups
	userGroups = append(userGroups, roleGroups...)
	return pruneDuplicates(userGroups), nil
}

func truncateToken(token string) string {
	if len(token) > 20 {
		return token[:20] + "..."
	}
	return token
}

// normalizeKeystoneURL removes trailing '/keystone' or trailing '/' from the baseURL
// This ensures consistent URL handling regardless of how the URL was provided
func normalizeKeystoneURL(baseURL string) string {
	// Remove trailing slash if present
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Remove trailing '/keystone' if present
	baseURL = strings.TrimSuffix(baseURL, "/keystone")

	return baseURL
}
