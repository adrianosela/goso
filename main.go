package main

import (
	"fmt"
	"log"
	"net/http"
	"reflect"

	"github.com/gorilla/mux"
	oso "github.com/osohq/go-oso"
)

type FeatureFlag struct {
	ID string
}

type Role struct {
	Name          string
	FeatureFlagID string
}

type OktaUser struct {
	Roles  []Role
	Groups []OktaGroup
}

type OktaGroup struct {
	Roles []Role
}

var (
	ffDb = map[string]FeatureFlag{
		"x": {ID: "x"},
		"y": {ID: "y"},
		"z": {ID: "y"},
	}
	usersDb = map[string]OktaUser{
		"larry":  {Roles: []Role{{Name: "viewer", FeatureFlagID: "x"}}},
		"anne":   {Roles: []Role{{Name: "viewer", FeatureFlagID: "y"}}},
		"graham": {Roles: []Role{{Name: "viewer", FeatureFlagID: "z"}}},
	}
	groupsDb = map[string]OktaGroup{
		"Internal Tools":             {Roles: []Role{{Name: "administrator", FeatureFlagID: "x"}}},
		"Infrastructure Engineering": {Roles: []Role{{Name: "viewer", FeatureFlagID: "x"}}},
		"Engineering":                {Roles: []Role{{Name: "viewer", FeatureFlagID: "z"}}},
	}
)

// This function is mocking an Okta Developer API call to
// https://developer.okta.com/docs/reference/api/users/#get-user-s-groups
func getOktaGroupsForUser(username string) []string {
	mockGroups := map[string][]string{
		"larry":  {"Infrastructure Engineering", "Engineering"},
		"graham": {"Internal Tools", "Engineering"},
	}

	groups, ok := mockGroups[username]
	if ok {
		return groups
	}

	return []string{}
}

func initializeRBAC(files ...string) (*oso.Oso, error) {
	rbac, err := oso.NewOso()
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize RBAC provider: %s", err)
	}

	for _, t := range []reflect.Type{reflect.TypeOf(FeatureFlag{}), reflect.TypeOf(OktaUser{})} {
		rbac.RegisterClass(t, nil)
	}

	if err := rbac.LoadFiles(files); err != nil {
		return nil, fmt.Errorf("Failed to load RBAC provider definition files: %s", err)
	}

	return &rbac, nil
}

func main() {
	rbac, err := initializeRBAC("perms.polar")
	if err != nil {
		log.Fatalf("Failed to initialize RBAC: %s", err)
	}

	r := mux.NewRouter()

	// RBAC testing endpoint
	r.Methods(http.MethodGet, http.MethodPost).Path("/feature-flag/{id}").HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			action := "view"
			if r.Method == http.MethodPost {
				action = "toggle"
			}

			authenticatedUser := r.Header.Get("MOCK_AUTENTICATED_USERNAME")
			if authenticatedUser == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("No bearer token provided"))
				return

			}

			id := mux.Vars(r)["id"]
			if id == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("No feature flag id provided"))
				return
			}

			user, ok := usersDb[authenticatedUser]
			if !ok { // user not in DB
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// decorate user object with groups
			for _, groupName := range getOktaGroupsForUser(authenticatedUser) {
				group, ok := groupsDb[groupName]
				if ok {
					user.Groups = append(user.Groups, group)
				}
			}

			ff, ok := ffDb[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintf("Feature flag \"%s\" was not found", id)))
				return
			}

			if err := rbac.Authorize(user, action, ff); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(fmt.Sprintf("User not authorized to %s feature flag \"%s\"", action, id)))
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Welcome to feature flag \"%s\"", id)))
			return
		},
	)

	// server liveliness check endpoint
	r.Methods(http.MethodGet).Path("/status").HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("I'm alive!"))
			return
		},
	)

	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Failed to serve: %s", err)
	}
}
