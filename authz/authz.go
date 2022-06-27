package authz

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	yaml "gopkg.in/yaml.v3"
)

var (
	// Groups is an in-memory collection of groups
	Groups = map[string]Group{}

	// Users is an in-memory collection of users
	Users = map[string]User{}
)

// Load loads the authz data onto memory
func Load(fname string) error {
	log.Printf("[authz] <INFO> Loading access control rules...")
	start := time.Now().UnixNano()

	fbytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return fmt.Errorf("Failed to read authz file: %s", err)
	}

	data := make(AccessControlRules)
	if err = yaml.Unmarshal(fbytes, &data); err != nil {
		return fmt.Errorf("Failed to unmarshal authz file: %s", err)
	}

	for resource, rules := range data {
		roleDefnsForResource := map[string]interface{}{} // used as a set for deduplication of roles per resource
		for _, rule := range rules {
			if _, ok := roleDefnsForResource[rule.Role]; ok {
				return fmt.Errorf("Duplicate role definition for role \"%s\" of resource \"%s\"", rule.Role, resource)
			} else {
				roleDefnsForResource[rule.Role] = true
			}
			for _, user := range rule.Users {
				if u, ok := Users[user]; ok {
					u.Roles = append(u.Roles, Role{Name: rule.Role, Resource: resource})
					Users[user] = u
				} else {
					Users[user] = User{
						Roles: []Role{{Name: rule.Role, Resource: resource}},
					}
				}
			}
			for _, group := range rule.Groups {
				if g, ok := Groups[group]; ok {
					g.Roles = append(g.Roles, Role{Name: rule.Role, Resource: resource})
					Groups[group] = g
				} else {
					Groups[group] = Group{
						Roles: []Role{{Name: rule.Role, Resource: resource}},
					}
				}
			}
		}
	}

	finish := time.Now().UnixNano()
	groupsByteSize, err := getRealSizeOf(Groups)
	if err != nil {
		log.Printf("[authz] <WARN> Failed to get the size of the groups map: %s", err)
	}
	usersByteSize, err := getRealSizeOf(Users)
	if err != nil {
		log.Printf("[authz] <WARN> Failed to get the size of the users map: %s", err)
	}
	log.Printf(
		"[authz] <INFO> Loading completed. Took %d ns, %d groups (%d bytes), %d users (%d bytes)",
		finish-start,
		len(Groups), groupsByteSize,
		len(Users), usersByteSize,
	)
	return nil
}

func getRealSizeOf(v interface{}) (int, error) {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0, err
	}
	return b.Len(), nil
}
