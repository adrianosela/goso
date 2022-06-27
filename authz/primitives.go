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

// Rule represents the access control rule for a resource
type Rule struct {
	Role   string
	Users  []string
	Groups []string
}

// AccessControlRules is a mapping of resource name to the
// the set of rules that govern access control for it
type AccessControlRules map[string][]Rule
