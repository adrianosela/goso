package main

import (
	"fmt"
	"log"
	"net/http"
	"reflect"

	"github.com/gorilla/mux"
	oso "github.com/osohq/go-oso"

	"github.com/adrianosela/goso/authz"
)

// This function is mocking an Okta Developer API call to
// https://developer.okta.com/docs/reference/api/users/#get-user-s-groups
func getOktaGroupsForUser(username string) []string {
	mockGroups := map[string][]string{
		"larry":  {"Infrastructure Engineering", "Engineering", "Everyone"},
		"anne":   {"Internal Tools", "Engineering", "Everyone"},
		"graham": {"Everyone"},
	}

	groups, ok := mockGroups[username]
	if ok {
		return groups
	}

	return []string{}
}

func initAuthorization() (*oso.Oso, error) {
	// initialize resources' role-identity mappings
	if err := authz.Load("authz.yaml"); err != nil {
		return nil, fmt.Errorf("Failed to initialize resources' role-identity mappings: %s", err)
	}

	// initialize oso definitions
	rbac, err := oso.NewOso()
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize OSO RBAC provider: %s", err)
	}
	for _, t := range []reflect.Type{reflect.TypeOf(authz.ProtectedResource{}), reflect.TypeOf(authz.User{})} {
		rbac.RegisterClass(t, nil)
	}
	if err := rbac.LoadFiles([]string{"perms.polar"}); err != nil {
		return nil, fmt.Errorf("Failed to load OSO RBAC provider definition files: %s", err)
	}
	return &rbac, nil
}

func main() {
	rbac, err := initAuthorization()
	if err != nil {
		log.Fatalf("Failed to initialize authorization mechanism: %s", err)
	}

	r := mux.NewRouter()

	// server liveliness check endpoint
	r.Methods(http.MethodGet).Path("/status").HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("I'm alive!"))
			return
		},
	)

	// RBAC testing endpoint
	r.Methods(http.MethodGet, http.MethodPost).Path("/resource/{name}").HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			action := "view"
			if r.Method == http.MethodPost {
				action = "toggle"
			}

			// user to mock passed in HTTP header
			authenticatedUser := r.Header.Get("AUTENTICATED_USER")
			if authenticatedUser == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("No bearer token provided"))
				return

			}

			name := mux.Vars(r)["name"]
			if name == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("No resource name provided"))
				return
			}

			user, ok := authz.Users[authenticatedUser]
			if !ok {
				user = &authz.User{Roles: []authz.Role{}}
			}

			// decorate user object with groups
			for _, groupName := range getOktaGroupsForUser(authenticatedUser) {
				group, ok := authz.Groups[groupName]
				if ok {
					user.Groups = append(user.Groups, group)
				}
			}

			if err := rbac.Authorize(user, action, authz.ProtectedResource{Name: name}); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(fmt.Sprintf("User not authorized for action \"%s\" on resource \"%s\"", action, name)))
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Performed action \"%s\" on resource \"%s\"", action, name)))
			return
		},
	)

	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Failed to serve: %s", err)
	}
}
