package keystonefed

// Minimal structs to parse Keystone JSON responses.

type authTokensResp struct {
	Token struct {
		User struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Email  string `json:"email"`
			Domain struct {
				ID string `json:"id"`
			} `json:"domain"`
		} `json:"user"`
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	} `json:"token"`
}

type groupsResp struct {
	Groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"groups"`
}

type keystoneIdentity struct {
	UserID    string
	Username  string
	Email     string
	Groups    []string
	ProjectID string
	DomainID  string
}
