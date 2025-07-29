# Keystone Federation (SAML/WebSSO) Connector

This connector lets Dex delegate authentication to **OpenStack Keystone** which itself delegates to a SAML IdP (Keystone as SP).

## Standard Flow (high-level)

1. Dex redirects browser to Keystone WebSSO endpoint:  
   `/v3/auth/OS-FEDERATION/websso/<protocol>?origin=<dex-callback>`
2. Keystone redirects to the SAML IdP.
3. IdP authenticates user and returns SAML to Keystone.
4. Keystone issues an **unscoped token** and redirects back to Dex callback, **adding the token to the query string as `ks_token`**.
5. Connector optionally exchanges it for a scoped token.
6. Connector calls Keystone to fetch user and group info.
7. Dex issues its ID/refresh tokens.

> **Important**: Step 4 requires Keystone (or a proxy) to append the token into the redirect URL. If your deployment can't do this, you must implement a relay or extend the connector.

## Federation SSO Flow (high-level)

The connector also supports direct federation SSO integration when `enableFederation` is set to `true`:

1. Dex redirects browser to the Shibboleth SSO login endpoint (`/sso/{IdP}/Shibboleth.sso/Login`) with a relay state containing callback information.
2. User is redirected to the SAML IdP (e.g., Okta) for authentication.
3. After authentication, IdP returns a SAML response.
4. The SAML response is submitted to the Shibboleth SAML2 POST endpoint.
5. Shibboleth establishes a session and sets federation cookies.
6. The connector uses these cookies to request a token from Keystone's federation auth endpoint.
7. Connector optionally exchanges it for a scoped token.
8. Connector calls Keystone to fetch user and group info.
9. Dex issues its ID/refresh tokens.

> **Note**: The federation flow is especially useful when Keystone cannot append the token to the redirect URL or when you need direct SSO integration with identity providers like Okta.

## Example config

```yaml
connectors:
  - type: keystonefed
    id: keystone-saml
    name: "Keystone SAML"
    config:
      baseURL: https://keystone.example.com:5000
      identityProviderID: myidp
      protocolID: saml2
      tokenInQuery: true
      projectID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee   # OR domainID
      timeoutSeconds: 15
