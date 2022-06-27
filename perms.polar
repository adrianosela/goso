allow(actor, action, resource) if
  has_permission(actor, action, resource);

actor User {}

resource ProtectedResource {
	permissions = ["view", "toggle"];
	roles = ["viewer", "administrator"];

	"view" if "viewer";
	"toggle" if "administrator";

	"viewer" if "administrator";
}

has_role(user: User, roleName: String, resource: ProtectedResource) if
  (role in user.Roles and role.Name = roleName and role.Resource = resource.Name) or
  (group in user.Groups and role in group.Roles and role.Name = roleName and role.Resource = resource.Name);
