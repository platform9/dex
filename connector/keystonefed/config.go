package keystonefed

import (
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds user-supplied YAML/JSON for the connector.
//
// Keystone must append the token into the redirect query (?ks_token=...).
// If it can't, set TokenInQuery to false and extend the connector for a relay path.
type Config struct {
	// BaseURL is Keystone base URL, e.g. https://keystone.test.com:5000
	BaseURL string `json:"baseURL"`
	// CustomerName is customer name to be used in group names
	CustomerName string `json:"customerName"`
	// AdminUsername is Keystone admin username
	AdminUsername string `json:"adminUsername"`
	// AdminPassword is Keystone admin password
	AdminPassword string `json:"adminPassword"`
	// IdentityProviderID is Keystone identity provider ID
	IdentityProviderID string `json:"identityProviderID"`
	// ProtocolID is protocol name, typically "saml2"
	ProtocolID string `json:"protocolID"`
	// ShibbolethLoginPath is Shibboleth SSO login endpoint path, typically '/sso/{IdP}/Shibboleth.sso/Login'
	ShibbolethLoginPath string `json:"shibbolethLoginPath,omitempty"`
	// ShibbolethSAML2PostPath is Shibboleth SSO SAML2 POST endpoint path, typically '/sso/{IdP}/Shibboleth.sso/SAML2/POST'
	ShibbolethSAML2PostPath string `json:"shibbolethSAML2PostPath,omitempty"`
	// FederationAuthPath is OS-FEDERATION identity providers auth path, typically '/keystone/v3/OS-FEDERATION/identity_providers/{IdP}/protocols/saml2/auth'
	FederationAuthPath string `json:"federationAuthPath,omitempty"`
	// DomainID is domain ID, typically "default"
	DomainID string `json:"domainID,omitempty"`
}

// Validate returns error if config is invalid.
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return errf("baseURL is required")
	}
	if c.IdentityProviderID == "" {
		return errf("identityProviderID is required")
	}
	if c.ProtocolID == "" {
		return errf("protocolID is required")
	}
	if c.ShibbolethLoginPath == "" {
		return errf("shibbolethLoginPath is required")
	}
	if c.ShibbolethSAML2PostPath == "" {
		return errf("shibbolethSAML2PostPath is required")
	}
	if c.FederationAuthPath == "" {
		return errf("federationAuthPath is required")
	}
	if c.DomainID == "" {
		return errf("domainID is required")
	}
	if c.CustomerName == "" {
		return errf("customerName is required")
	}
	return nil
}

// Open returns a connector using the configuration
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	return New(*c, logger)
}
