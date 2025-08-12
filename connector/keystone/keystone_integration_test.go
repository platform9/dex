package keystone

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/dexidp/dex/connector"
)

// TestKeystoneConnectorIntegration tests the Keystone connector against a real Keystone service
func TestKeystoneConnectorIntegration(t *testing.T) {
	// Skip if integration test environment variables are not set
	keystoneHost := os.Getenv("DEX_KEYSTONE_URL")
	if keystoneHost == "" {
		t.Skip("DEX_KEYSTONE_URL not set, skipping integration tests")
	}

	// Use default admin credentials that should work with the OpenIO Keystone image
	adminUser := os.Getenv("DEX_KEYSTONE_ADMIN_USER")
	if adminUser == "" {
		adminUser = "admin"
	}

	adminPass := os.Getenv("DEX_KEYSTONE_ADMIN_PASS")
	if adminPass == "" {
		adminPass = "admin"
	}

	// Test connector configuration
	config := Config{
		Host:          keystoneHost,
		Domain:        "default",
		AdminUsername: adminUser,
		AdminPassword: adminPass,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Test connector creation
	keystoneConnector, err := config.Open("test-keystone", logger)
	if err != nil {
		t.Fatalf("Failed to create Keystone connector: %v", err)
	}

	keystoneConn, ok := keystoneConnector.(*conn)
	if !ok {
		t.Fatal("Expected Keystone connector type")
	}

	ctx := context.Background()

	t.Run("AdminTokenAuthentication", func(t *testing.T) {
		// Test admin token retrieval
		token, err := keystoneConn.getAdminTokenUnscoped(ctx)
		if err != nil {
			t.Fatalf("Failed to get admin token: %v", err)
		}
		if token == "" {
			t.Fatal("Expected non-empty admin token")
		}
		t.Logf("Successfully obtained admin token: %s", token[:10]+"...")
	})

	t.Run("AdminUserLogin", func(t *testing.T) {
		// Test admin user login through the connector
		scopes := connector.Scopes{
			OfflineAccess: false,
			Groups:        true,
		}

		identity, validPassword, err := keystoneConn.Login(ctx, scopes, adminUser, adminPass)
		if err != nil {
			t.Fatalf("Admin login failed: %v", err)
		}
		if !validPassword {
			t.Fatal("Expected valid password for admin user")
		}
		if identity.Username != adminUser {
			t.Fatalf("Expected username %s, got %s", adminUser, identity.Username)
		}
		if identity.UserID == "" {
			t.Fatal("Expected non-empty user ID")
		}
		t.Logf("Admin login successful - Username: %s, UserID: %s, Groups: %v",
			identity.Username, identity.UserID, identity.Groups)
	})

	t.Run("TokenModeAuthentication", func(t *testing.T) {
		// First get a valid token
		token, err := keystoneConn.getAdminTokenUnscoped(ctx)
		if err != nil {
			t.Fatalf("Failed to get admin token: %v", err)
		}

		// Test token-based authentication
		scopes := connector.Scopes{
			OfflineAccess: false,
			Groups:        false,
		}

		identity, validPassword, err := keystoneConn.Login(ctx, scopes, "_TOKEN_", token)
		if err != nil {
			t.Fatalf("Token authentication failed: %v", err)
		}
		if !validPassword {
			t.Fatal("Expected valid token authentication")
		}
		if identity.Username == "" {
			t.Fatal("Expected non-empty username from token")
		}
		if identity.UserID == "" {
			t.Fatal("Expected non-empty user ID from token")
		}
		t.Logf("Token authentication successful - Username: %s, UserID: %s",
			identity.Username, identity.UserID)
	})

	t.Run("InvalidCredentials", func(t *testing.T) {
		scopes := connector.Scopes{
			OfflineAccess: false,
			Groups:        false,
		}

		_, validPassword, err := keystoneConn.Login(ctx, scopes, "invalid_user", "invalid_pass")
		if err == nil {
			t.Fatal("Expected error for invalid credentials")
		}
		if validPassword {
			t.Fatal("Expected invalid password for non-existent user")
		}
		t.Logf("Invalid credentials correctly rejected: %v", err)
	})

	t.Run("ConnectorRefresh", func(t *testing.T) {
		// First perform a login to get connector data
		scopes := connector.Scopes{
			OfflineAccess: false,
			Groups:        true,
		}

		identity, validPassword, err := keystoneConn.Login(ctx, scopes, adminUser, adminPass)
		if err != nil {
			t.Fatalf("Initial login failed: %v", err)
		}
		if !validPassword {
			t.Fatal("Expected valid password for admin user")
		}

		// Test refresh functionality
		refreshedIdentity, err := keystoneConn.Refresh(ctx, scopes, identity)
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}
		if refreshedIdentity.Username != identity.Username {
			t.Fatalf("Expected username %s, got %s", identity.Username, refreshedIdentity.Username)
		}
		if refreshedIdentity.UserID != identity.UserID {
			t.Fatalf("Expected user ID %s, got %s", identity.UserID, refreshedIdentity.UserID)
		}
		t.Logf("Refresh successful - Username: %s, UserID: %s, Groups: %v",
			refreshedIdentity.Username, refreshedIdentity.UserID, refreshedIdentity.Groups)
	})

	t.Run("HelperFunctions", func(t *testing.T) {
		// Test hostname extraction
		hostname, err := keystoneConn.getHostname()
		if err != nil {
			t.Fatalf("Failed to get hostname: %v", err)
		}
		if hostname == "" {
			t.Fatal("Expected non-empty hostname")
		}
		t.Logf("Hostname: %s", hostname)

		// Test admin token for API calls
		token, err := keystoneConn.getAdminTokenUnscoped(ctx)
		if err != nil {
			t.Fatalf("Failed to get admin token: %v", err)
		}

		// Test token info retrieval
		tokenInfo, err := keystoneConn.getTokenInfo(ctx, token)
		if err != nil {
			t.Fatalf("Failed to get token info: %v", err)
		}
		if tokenInfo.User.Name == "" {
			t.Fatal("Expected non-empty user name in token info")
		}
		t.Logf("Token info - User: %s, Domain: %s", tokenInfo.User.Name, tokenInfo.User.Domain.Name)

		// Test user existence check
		exists, err := keystoneConn.checkIfUserExists(ctx, tokenInfo.User.ID, token)
		if err != nil {
			t.Fatalf("Failed to check user existence: %v", err)
		}
		if !exists {
			t.Fatal("Expected admin user to exist")
		}
		t.Logf("User existence check passed for user ID: %s", tokenInfo.User.ID)
	})
}

// TestKeystoneConnectorConfiguration tests various configuration scenarios
func TestKeystoneConnectorConfiguration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("MissingHost", func(t *testing.T) {
		config := Config{
			Domain:        "default",
			AdminUsername: "admin",
			AdminPassword: "admin",
		}

		_, err := config.Open("test", logger)
		if err == nil {
			t.Fatal("Expected error for missing host")
		}
		t.Logf("Correctly rejected missing host: %v", err)
	})

	t.Run("ValidConfiguration", func(t *testing.T) {
		config := Config{
			Host:          "http://localhost:5000",
			Domain:        "default",
			AdminUsername: "admin",
			AdminPassword: "admin",
		}

		keystoneConnector, err := config.Open("test", logger)
		if err != nil {
			t.Fatalf("Failed to create connector with valid config: %v", err)
		}

		keystoneConn, ok := keystoneConnector.(*conn)
		if !ok {
			t.Fatal("Expected Keystone connector type")
		}

		if keystoneConn.Host != config.Host {
			t.Fatalf("Expected host %s, got %s", config.Host, keystoneConn.Host)
		}
		if keystoneConn.AdminUsername != config.AdminUsername {
			t.Fatalf("Expected admin username %s, got %s", config.AdminUsername, keystoneConn.AdminUsername)
		}
		if keystoneConn.Domain.Name != config.Domain {
			t.Fatalf("Expected domain %s, got %s", config.Domain, keystoneConn.Domain.Name)
		}
	})

	t.Run("InsecureSkipVerify", func(t *testing.T) {
		config := Config{
			Host:               "https://localhost:5000",
			Domain:             "default",
			AdminUsername:      "admin",
			AdminPassword:      "admin",
			InsecureSkipVerify: true,
		}

		keystoneConnector, err := config.Open("test", logger)
		if err != nil {
			t.Fatalf("Failed to create connector with InsecureSkipVerify: %v", err)
		}

		keystoneConn, ok := keystoneConnector.(*conn)
		if !ok {
			t.Fatal("Expected Keystone connector type")
		}

		// Verify TLS config is set for insecure
		if keystoneConn.client.Transport == nil {
			t.Fatal("Expected HTTP transport to be configured")
		}
	})
}
