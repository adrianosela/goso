allow(actor, action, resource) if
  has_permission(actor, action, resource);

actor OktaUser {}

resource FeatureFlag {
	permissions = ["toggle", "view"];
	roles = ["administrator", "viewer"];

	"view" if "viewer";
	"toggle" if "administrator";

	"viewer" if "administrator";
}

has_role(user: OktaUser, roleName: String, featureFlag: FeatureFlag) if
  (role in user.Roles and role.Name = roleName and role.FeatureFlagID = featureFlag.ID) or
  (group in user.Groups and role in group.Roles and role.Name = roleName and role.FeatureFlagID = featureFlag.ID);
