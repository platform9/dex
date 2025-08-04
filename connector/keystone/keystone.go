// Package keystone provides authentication strategy using Keystone.
package keystone

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

type conn struct {
	Domain        domainKeystone
	Host          string
	AdminUsername string
	AdminPassword string
	client        *http.Client
	Logger        log.Logger
	CustomerName  string
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

var (
	_ connector.PasswordConnector = &conn{}
	_ connector.RefreshConnector  = &conn{}
)

// Open returns an authentication strategy using Keystone.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	domain := domainKeystone{
		Name: c.Domain,
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.InsecureSkipVerify,
		},
	}
	client := &http.Client{Transport: tr}
	return &conn{
		Domain:        domain,
		Host:          c.Host,
		AdminUsername: c.AdminUsername,
		AdminPassword: c.AdminPassword,
		Logger:        logger,
		client:        client,
		CustomerName:  c.CustomerName,
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

	if scopes.Groups {
		p.Logger.Infof("groups scope requested, fetching groups")
		var err error
		adminToken, err := p.getAdminTokenUnscoped(ctx)
		if err != nil {
			return identity, false, fmt.Errorf("keystone: failed to obtain admin token: %v", err)
		}
		identity.Groups, err = p.getGroups(ctx, adminToken, tokenInfo)
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
	token, err := p.getAdminTokenUnscoped(ctx)
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

	if scopes.Groups {
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
						Domain:   p.Domain,
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
	baseURL := normalizeKeystoneURL(p.Host)
	authTokenURL := baseURL + "/keystone/v3/auth/tokens/"
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

func (p *conn) getAdminTokenUnscoped(ctx context.Context) (string, error) {
	baseURL := normalizeKeystoneURL(p.Host)
	return getAdminTokenUnscoped(ctx, p.client, baseURL, p.AdminUsername, p.AdminPassword)
}

func (p *conn) checkIfUserExists(ctx context.Context, userID string, token string) (bool, error) {
	user, err := p.getUser(ctx, userID, token)
	return user != nil, err
}

func (p *conn) getGroups(ctx context.Context, token string, tokenInfo *tokenInfo) ([]string, error) {
	baseURL := normalizeKeystoneURL(p.Host)
	return getAllGroupsForUser(ctx, p.client, baseURL, token, p.CustomerName, p.Domain.ID, tokenInfo, p.Logger)
}

func (p *conn) getUser(ctx context.Context, userID string, token string) (*userResponse, error) {
	baseURL := normalizeKeystoneURL(p.Host)
	return getUser(ctx, p.client, baseURL, userID, token)
}

func (p *conn) getTokenInfo(ctx context.Context, token string) (*tokenInfo, error) {
	baseURL := normalizeKeystoneURL(p.Host)
	return getTokenInfo(ctx, p.client, baseURL, token, p.Logger)
}
