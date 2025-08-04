package keystone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

var (
	_ connector.CallbackConnector = &FederationConnector{}
	_ connector.RefreshConnector  = &FederationConnector{}
)

// FederationConnector implements the connector interface for Keystone federation authentication
type FederationConnector struct {
	cfg    FederationConfig
	client *http.Client
	logger log.Logger

	// Stores callback information for the federation flow
	callbackURL string
	state       string
}

// Validate returns error if config is invalid.
func (c *FederationConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain field is required in config")
	}
	if c.Host == "" {
		return fmt.Errorf("host field is required in config")
	}
	if c.AdminUsername == "" {
		return fmt.Errorf("keystoneUsername field is required in config")
	}
	if c.AdminPassword == "" {
		return fmt.Errorf("keystonePassword field is required in config")
	}
	if c.CustomerName == "" {
		return fmt.Errorf("customerName field is required in config")
	}
	if c.ShibbolethLoginPath == "" {
		return fmt.Errorf("shibbolethLoginPath field is required in config")
	}
	if c.FederationAuthPath == "" {
		return fmt.Errorf("federationAuthPath field is required in config")
	}
	return nil
}

// Open returns a connector using the federation configuration
func (c *FederationConfig) Open(id string, logger log.Logger) (connector.Connector, error) {
	return NewFederationConnector(*c, logger)
}

func NewFederationConnector(cfg FederationConfig, logger log.Logger) (*FederationConnector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &FederationConnector{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(30) * time.Second,
		},
		logger: logger,
	}, nil
}

func (c *FederationConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	c.logger.Infof("LoginURL called with callbackURL=%s, state=%s", callbackURL, state)
	ksBase := normalizeKeystoneURL(c.cfg.Host)

	// Store the callback URL and state in the connector for use during callback handling
	c.callbackURL = callbackURL
	c.state = state
	c.logger.Infof("Stored callback URL=%s and state=%s in connector", callbackURL, state)

	// Use Shibboleth SSO login path for federation
	ssoLoginPath := c.cfg.ShibbolethLoginPath

	// Construct the Shibboleth login URL
	u, err := url.Parse(fmt.Sprintf("%s%s", ksBase, ssoLoginPath))
	if err != nil {
		return "", fmt.Errorf("parsing SSO login URL: %w", err)
	}

	// The target will be passed through the entire federation flow.
	// target is nothing but the redirect url that will be used by shibboleth to redirect back to Dex.
	target := fmt.Sprintf("%s?state=%s", callbackURL, state)
	q := u.Query()
	q.Set("target", target)
	c.logger.Infof("Setting target=%s for federation login", target)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *FederationConnector) HandleCallback(scopes connector.Scopes, r *http.Request) (connector.Identity, error) {
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

	// Log state information
	c.logger.Infof("Processing callback for state=%s", state)

	// Extract federation cookies and use them to get a keystone token
	ksToken, err = c.getKeystoneTokenFromFederation(r)
	if err != nil {
		c.logger.Errorf("Error getting token from federation cookies: %v", err)
		return connector.Identity{}, fmt.Errorf("getting token from federation cookies: %w", err)
	}
	c.logger.Infof("Successfully obtained token from federation cookies")

	ksBase := normalizeKeystoneURL(c.cfg.Host)
	c.logger.Infof("Retrieving user info with token: %s", truncateToken(ksToken))
	tokenInfo, err = getTokenInfo(r.Context(), c.client, ksBase, ksToken, c.logger)
	if err != nil {
		return connector.Identity{}, err
	}
	if scopes.Groups {
		c.logger.Infof("groups scope requested, fetching groups")
		var err error
		adminToken, err := getAdminTokenUnscoped(r.Context(), c.client, ksBase, c.cfg.AdminUsername, c.cfg.AdminPassword)
		if err != nil {
			return identity, fmt.Errorf("keystone: failed to obtain admin token: %v", err)
		}
		identity.Groups, err = getAllGroupsForUser(r.Context(), c.client, ksBase, adminToken, c.cfg.CustomerName, c.cfg.Domain, tokenInfo, c.logger)
		if err != nil {
			return connector.Identity{}, err
		}
	}
	identity.Username = tokenInfo.User.Name
	identity.UserID = tokenInfo.User.ID

	user, err := getUser(r.Context(), c.client, ksBase, tokenInfo.User.ID, ksToken)
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

// getKeystoneTokenFromFederation gets a Keystone token using an existing federation session.
// This method extracts federation cookies from the request and uses them to authenticate
// with Keystone's federation endpoint.
func (c *FederationConnector) getKeystoneTokenFromFederation(r *http.Request) (string, error) {
	c.logger.Infof("Getting Keystone token from federation cookies")
	ksBase := normalizeKeystoneURL(c.cfg.Host)
	c.logger.Infof("Using federation auth path: %s", c.cfg.FederationAuthPath)

	// Prepare the federation auth request
	federationAuthURL := fmt.Sprintf("%s%s", ksBase, c.cfg.FederationAuthPath)
	c.logger.Infof("Requesting Keystone token from: %s", federationAuthURL)

	req, err := http.NewRequest("GET", federationAuthURL, nil)
	if err != nil {
		c.logger.Errorf("Error creating federation auth request: %v", err)
		return "", fmt.Errorf("creating federation auth request: %w", err)
	}

	// Copy all cookies from the original request to maintain the federation session
	for _, cookie := range r.Cookies() {
		c.logger.Infof("Adding cookie to federation request: %s", cookie.Name)
		req.AddCookie(cookie)
	}

	// Copy relevant headers that might be needed for federation
	if userAgent := r.Header.Get("User-Agent"); userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		req.Header.Set("Referer", referer)
	}

	c.logger.Infof("Federation auth request headers: %v", req.Header)

	// Use a client that doesn't automatically follow redirects
	clientNoRedirect := &http.Client{
		Timeout: c.client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := clientNoRedirect.Do(req)
	if err != nil {
		c.logger.Errorf("Error executing federation auth request: %v", err)
		return "", fmt.Errorf("executing federation auth request: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Infof("Federation auth response status: %s", resp.Status)
	c.logger.Infof("Federation auth response headers: %v", resp.Header)

	// Extract the token from the X-Subject-Token header
	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		c.logger.Error("No X-Subject-Token found in federation auth response")
		return "", fmt.Errorf("no X-Subject-Token found in federation auth response")
	}

	c.logger.Infof("Successfully obtained Keystone token from federation: %s", truncateToken(token))
	return token, nil
}

// Close does nothing since HTTP connections are closed automatically.
func (c *FederationConnector) Close() error {
	return nil
}

// Refresh is used to refresh identity during token refresh.
// It checks if the user still exists and refreshes their group membership.
func (c *FederationConnector) Refresh(
	ctx context.Context, scopes connector.Scopes, identity connector.Identity,
) (connector.Identity, error) {
	c.logger.Infof("Refresh called for user %s", identity.UserID)
	ksBase := normalizeKeystoneURL(c.cfg.Host)

	// Get admin token to perform operations
	adminToken, err := getAdminTokenUnscoped(ctx, c.client, ksBase, c.cfg.AdminUsername, c.cfg.AdminPassword)
	if err != nil {
		return identity, fmt.Errorf("keystone federation: failed to obtain admin token: %v", err)
	}

	// Check if the user still exists
	user, err := getUser(ctx, c.client, ksBase, identity.UserID, adminToken)
	if err != nil {
		return identity, fmt.Errorf("keystone federation: failed to get user: %v", err)
	}
	if user == nil {
		return identity, fmt.Errorf("keystone federation: user %q does not exist", identity.UserID)
	}

	// Create a token info object with basic user info
	tokenInfo := &tokenInfo{
		User: userKeystone{
			Name: identity.Username,
			ID:   identity.UserID,
		},
	}

	// If there is a token associated with this refresh token, use that to get more info
	var data connectorData
	if err := json.Unmarshal(identity.ConnectorData, &data); err != nil {
		return identity, fmt.Errorf("keystone federation: unmarshal connector data: %v", err)
	}

	// If we have a stored token, try to use it to get token info
	if len(data.Token) > 0 {
		c.logger.Infof("Using stored token to get token info: %s", truncateToken(data.Token))
		tokenInfoFromStored, err := getTokenInfo(ctx, c.client, ksBase, data.Token, c.logger)
		if err == nil {
			// Only use the stored token info if we could retrieve it successfully
			tokenInfo = tokenInfoFromStored
		} else {
			c.logger.Warnf("Could not get token info from stored token: %v", err)
		}
	}

	// If groups scope is requested, refresh the groups
	if scopes.Groups {
		c.logger.Infof("Refreshing groups for user %s", identity.UserID)
		var err error
		identity.Groups, err = getAllGroupsForUser(ctx, c.client, ksBase, adminToken, c.cfg.CustomerName, c.cfg.Domain, tokenInfo, c.logger)
		if err != nil {
			return identity, fmt.Errorf("keystone federation: failed to get groups: %v", err)
		}
	}

	return identity, nil
}
