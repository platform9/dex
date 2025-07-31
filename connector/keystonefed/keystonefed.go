package keystonefed

import (
	"encoding/json"
	"fmt"
	"io"

	//"log"
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
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 10
	}
	return &Connector{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
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

	// Add the relay state containing our callback URL and state
	// The relay state will be passed through the entire federation flow
	//relayState := url.QueryEscape(fmt.Sprintf("callback=%s&state=%s",
	//	url.QueryEscape(callbackURL),
	//	url.QueryEscape(state)))
	relayState := fmt.Sprintf("%s&state=%s", callbackURL, state)
	q := u.Query()
	q.Set("RelayState", relayState)
	c.logger.Infof("Setting RelayState=%s for federation login", relayState)
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

	// Get state from query parameters
	state := r.URL.Query().Get("state")
	c.logger.Infof("State from query: %s", state)
	if state == "" {
		c.logger.Error("Missing state in request")
		return connector.Identity{}, fmt.Errorf("missing state")
	}

	// Handle federation flow if enabled
	c.logger.Infof("Processing federation flow with EnableFederation=true")
	// Check if this is a direct SAML response from an IdP
	if r.Method == "POST" && r.FormValue("SAMLResponse") != "" {
		// Extract the SAML response
		samlResponse := r.FormValue("SAMLResponse")
		c.logger.Infof("Received direct SAML response (truncated): %s...", samlResponse[:min(len(samlResponse), 50)])
		c.logger.Infof("RelayState from SAML response: %s", r.FormValue("RelayState"))

		// Use the SAML response to get a token from Keystone
		ksToken, err = c.getKeystoneTokenFromSAML(samlResponse, r.FormValue("RelayState"))
		if err != nil {
			c.logger.Errorf("Error getting token from SAML: %v", err)
			return connector.Identity{}, fmt.Errorf("getting token from SAML: %w", err)
		}
		c.logger.Infof("Successfully obtained token from SAML response")
	} else {
		// Check for a federation cookie indicating we've completed authentication
		cookie, err := r.Cookie("_shibsession_") // This name might vary
		if err == nil && cookie != nil {
			// Get a token using the federation auth endpoint
			ksToken, err = c.getKeystoneTokenFromFederation(r)
			if err != nil {
				return connector.Identity{}, fmt.Errorf("getting keystone token from federation: %w", err)
			}
		} else {
			c.logger.Info("No SAML response found, checking for federation cookies")
			// Extract federation cookies and use them to get a token
			ksToken, err = c.getKeystoneTokenFromFederation(r)
			if err != nil {
				c.logger.Errorf("Error getting token from federation cookies: %v", err)
				return connector.Identity{}, fmt.Errorf("getting token from federation cookies: %w", err)
			}
			c.logger.Infof("Successfully obtained token from federation cookies")
		}
	}

	// Optionally rescope
	tokenToUse := ksToken
	if c.cfg.ProjectID != "" || c.cfg.DomainID != "" {
		tokenToUse, err = c.scopeToken(ksToken)
		if err != nil {
			return connector.Identity{}, fmt.Errorf("scoping token: %w", err)
		}
	}

	c.logger.Infof("Retrieving user info with token: %s", truncateToken(ksToken))
	user, groups, err := c.fetchUserAndGroups(tokenToUse)
	if err != nil {
		return connector.Identity{}, err
	}

	return connector.Identity{
		UserID:        user.UserID,
		Username:      user.Username,
		Email:         user.Email,
		Groups:        groups,
		ConnectorData: []byte(tokenToUse), // store token if you want to refresh attributes later
	}, nil
}

// scopeToken exchanges an unscoped token for a project/domain-scoped token.
func (c *Connector) scopeToken(unscoped string) (string, error) {
	type scopeReq struct {
		Auth struct {
			Identity struct {
				Methods []string `json:"methods"`
				Token   struct {
					ID string `json:"id"`
				} `json:"token"`
			} `json:"identity"`
			Scope json.RawMessage `json:"scope"`
		} `json:"auth"`
	}
	var sr scopeReq
	sr.Auth.Identity.Methods = []string{"token"}
	sr.Auth.Identity.Token.ID = unscoped

	if c.cfg.ProjectID != "" {
		sr.Auth.Scope = json.RawMessage([]byte(fmt.Sprintf(`{"project": {"id": "%s"}}`, c.cfg.ProjectID)))
	} else {
		sr.Auth.Scope = json.RawMessage([]byte(fmt.Sprintf(`{"domain": {"id": "%s"}}`, c.cfg.DomainID)))
	}

	payload, _ := json.Marshal(sr)
	req, _ := http.NewRequest("POST", strings.TrimRight(c.cfg.BaseURL, "/")+"/v3/auth/tokens", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("scope token failed: %s body=%s", resp.Status, string(body))
	}
	return resp.Header.Get("X-Subject-Token"), nil
}

func (c *Connector) fetchUserAndGroups(token string) (keystoneIdentity, []string, error) {
	id, email, name, domainID, projectID, err := c.inspectToken(token)
	if err != nil {
		return keystoneIdentity{}, nil, err
	}

	if email == "" {
		// Fallback to /v3/users/{id}
		if e, err2 := c.getUserEmail(token, id); err2 == nil {
			email = e
		}
	}

	groups, err := c.getGroups(token, id)
	if err != nil {
		return keystoneIdentity{}, nil, err
	}

	return keystoneIdentity{
		UserID:    id,
		Username:  name,
		Email:     email,
		Groups:    groups,
		ProjectID: projectID,
		DomainID:  domainID,
	}, groups, nil
}

// inspectToken calls GET /v3/auth/tokens to retrieve token info.
func (c *Connector) inspectToken(token string) (userID, email, name, domainID, projectID string, err error) {
	req, _ := http.NewRequest("GET", strings.TrimRight(c.cfg.BaseURL, "/")+"/v3/auth/tokens", nil)
	req.Header.Set("X-Subject-Token", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("inspect token failed: %s body=%s", resp.Status, string(b))
		return
	}

	var at authTokensResp
	if err = json.NewDecoder(resp.Body).Decode(&at); err != nil {
		return
	}
	userID = at.Token.User.ID
	name = at.Token.User.Name
	email = at.Token.User.Email
	domainID = at.Token.User.Domain.ID
	projectID = at.Token.Project.ID
	return
}

func (c *Connector) getUserEmail(token, userID string) (string, error) {
	req, _ := http.NewRequest("GET", strings.TrimRight(c.cfg.BaseURL, "/")+"/v3/users/"+userID, nil)
	req.Header.Set("X-Auth-Token", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("users get failed: %s", resp.Status)
	}
	var ur struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ur); err != nil {
		return "", err
	}
	return ur.User.Email, nil
}

func (c *Connector) getGroups(token, userID string) ([]string, error) {
	req, _ := http.NewRequest("GET", strings.TrimRight(c.cfg.BaseURL, "/")+"/v3/groups?user_id="+userID, nil)
	req.Header.Set("X-Auth-Token", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("groups list failed: %s", resp.Status)
	}
	var gr groupsResp
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(gr.Groups))
	for _, g := range gr.Groups {
		out = append(out, g.Name)
	}
	return out, nil
}

// getKeystoneTokenFromSAML submits a SAML response to the Shibboleth SAML2 POST endpoint
// to establish a session and then gets a Keystone token via the federation auth endpoint.
func (c *Connector) getKeystoneTokenFromSAML(samlResponse, relayState string) (string, error) {
	c.logger.Infof("Getting Keystone token from SAML response with RelayState: %s", relayState)
	ksBase := strings.TrimRight(c.cfg.BaseURL, "/")

	// Replace any {IdP} placeholder with the actual IdentityProviderID
	saml2PostPath := strings.Replace(c.cfg.ShibbolethSAML2PostPath, "{IdP}", c.cfg.IdentityProviderID, -1)
	c.logger.Infof("Using Shibboleth SAML2 POST path: %s", saml2PostPath)

	// Prepare the SAML POST request to establish a federation session
	form := url.Values{}
	form.Add("SAMLResponse", samlResponse)
	if relayState != "" {
		c.logger.Infof("Adding RelayState to SAML POST: %s", relayState)
		form.Add("RelayState", relayState)
	} else {
		c.logger.Warn("No RelayState provided for SAML POST request")
	}

	// Submit SAML response to Shibboleth SAML2 POST endpoint
	samlPostURL := fmt.Sprintf("%s%s", ksBase, saml2PostPath)
	c.logger.Infof("Submitting SAML response to: %s", samlPostURL)
	req, err := http.NewRequest("POST", samlPostURL, strings.NewReader(form.Encode()))
	if err != nil {
		c.logger.Errorf("Error creating SAML POST request: %v", err)
		return "", fmt.Errorf("creating SAML POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.logger.Infof("SAML POST request headers: %v", req.Header)

	// Use a client that doesn't automatically follow redirects
	clientNoRedirect := &http.Client{
		Timeout: c.client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := clientNoRedirect.Do(req)
	if err != nil {
		return "", fmt.Errorf("submitting SAML response: %w", err)
	}
	defer resp.Body.Close()

	// Extract federation cookie(s) from response
	c.logger.Infof("Response status from SAML POST: %s", resp.Status)
	c.logger.Infof("Response headers: %v", resp.Header)

	var federationCookies []*http.Cookie
	for _, cookie := range resp.Cookies() {
		c.logger.Infof("Cookie in response: Name=%s, Domain=%s, Path=%s", cookie.Name, cookie.Domain, cookie.Path)
		if strings.Contains(cookie.Name, "_shibsession_") ||
			strings.Contains(cookie.Name, "_saml_") ||
			strings.Contains(cookie.Name, "_openstack_") {
			c.logger.Infof("Found federation cookie: %s", cookie.Name)
			federationCookies = append(federationCookies, cookie)
		}
	}

	if len(federationCookies) == 0 {
		c.logger.Error("No federation cookies found in response")
		return "", fmt.Errorf("no federation cookies found in response")
	} else {
		c.logger.Infof("Found %d federation cookies", len(federationCookies))
	}

	// Now use the federation cookies to get a token from Keystone
	return c.getKeystoneTokenWithFederationCookies(federationCookies)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
