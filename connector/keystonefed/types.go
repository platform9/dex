package keystonefed

// Minimal structs to parse Keystone JSON responses.

// type keystoneIdentity struct {
// 	UserID    string
// 	Username  string
// 	Email     string
// 	Groups    []string
// 	ProjectID string
// 	DomainID  string
// }

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

type loginRequestData struct {
	auth `json:"auth"`
}

type auth struct {
	Identity identity `json:"identity"`
	//Scope    domainScope `json:"scope"`
}

//	type loginRequestDataDomain struct {
//		authDomain `json:"auth"`
//	}
// type authDomain struct {
// 	Identity identity    `json:"identity"`
// 	Scope    domainScope `json:"scope"`
// }

type identity struct {
	Methods  []string `json:"methods"`
	Password password `json:"password"`
}

// type domainScope struct {
// 	Domain domainKeystone `json:"domain"`
// }

type password struct {
	User user `json:"user"`
}

type user struct {
	Name     string         `json:"name"`
	Domain   domainKeystone `json:"domain"`
	Password string         `json:"password"`
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

type project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DomainID    string `json:"domain_id"`
	Description string `json:"description"`
}
type identifierContainer struct {
	ID string `json:"id"`
}

type projectScope struct {
	Project identifierContainer `json:"project"`
}

type roleAssignment struct {
	Scope projectScope        `json:"scope"`
	User  identifierContainer `json:"user"`
	Role  identifierContainer `json:"role"`
}

type connectorData struct {
	Token string `json:"token"`
}

type getRoleAssignmentsOptions struct {
	userID    string
	groupID   string
	projectID string
}
