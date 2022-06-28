package authz

// ProtectedResource represents a uniquely named, rbac-protected resource.
type ProtectedResource struct {
	Name string
}

// Role represents a role with privilege over a resource
type Role struct {
	Name     string
	Resource string
}

// Group represents privilege held by a group
type Group struct {
	Roles []Role
}

// User represents privilege held by a user
type User struct {
	Roles  []Role
	Groups []*Group
}

// IdentitySet represents a set of identities
type IdentitySet struct {
	Users  []string
	Groups []string
}

// RoleMap is a map of role name to the set
// of identities which can assume the role
type RoleMap map[string]IdentitySet

// AccessControlRules is a mapping of resource name to
// the role map which governs access control for it
type AccessControlRules map[string]RoleMap
