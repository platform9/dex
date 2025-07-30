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
	// Keystone base URL, e.g. https://keystone.example.com:5000
	BaseURL string `json:"baseURL"`

	// Keystone federation identifiers
	IdentityProviderID string `json:"identityProviderID"` // e.g. "myidp"
	ProtocolID         string `json:"protocolID"`         // usually "saml2"

	// Optional static scope (pick one)
	ProjectID string `json:"projectID,omitempty"`
	DomainID  string `json:"domainID,omitempty"`

	// True if Keystone (or a proxy) puts the token into the redirect query (?ks_token=...)
	TokenInQuery bool `json:"tokenInQuery"`

	// HTTP timeout (seconds)
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	// Enable SSO federation flow using Shibboleth
	EnableFederation bool `json:"enableFederation,omitempty"`

	// Shibboleth SSO login endpoint path, typically '/sso/{IdP}/Shibboleth.sso/Login'
	ShibbolethLoginPath string `json:"shibbolethLoginPath,omitempty"`

	// Shibboleth SSO SAML2 POST endpoint path, typically '/sso/{IdP}/Shibboleth.sso/SAML2/POST'
	ShibbolethSAML2PostPath string `json:"shibbolethSAML2PostPath,omitempty"`

	// OS-FEDERATION identity providers auth path, typically '/keystone/v3/OS-FEDERATION/identity_providers/{IdP}/protocols/saml2/auth'
	FederationAuthPath string `json:"federationAuthPath,omitempty"`
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
	if c.ProjectID != "" && c.DomainID != "" {
		return errf("only one of projectID or domainID may be set")
	}

	// Validate federation parameters if federation is enabled
	if c.EnableFederation {
		if c.ShibbolethLoginPath == "" {
			return errf("shibbolethLoginPath is required when federation is enabled")
		}
		if c.ShibbolethSAML2PostPath == "" {
			return errf("shibbolethSAML2PostPath is required when federation is enabled")
		}
		if c.FederationAuthPath == "" {
			return errf("federationAuthPath is required when federation is enabled")
		}
	}

	return nil
}

// Open returns a connector using the configuration
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	return New(*c, logger)
}
