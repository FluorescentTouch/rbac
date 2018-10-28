package rbac

import "sync"

// RBAC describes controller that operates Users, Roles and Object-Action-based Permissions
// For usage all objects( Users, Roles, Permissions has to be registered using correlated methods.
type RBAC struct {
	registeredPermissions map[Permission]struct{}
	registeredRoles map[Role]struct{}
	registeredUsers map[User]struct{}

	perms2roles map[Role]map[Permission]struct{}
	roles2users map[User]map[Role]struct{}

	mutex *sync.RWMutex
}

// NewRBAC creates instance of RBAC controller
func NewRBAC() *RBAC {
	return &RBAC{
		registeredPermissions: make(map[Permission]struct{}),
		registeredRoles: make(map[Role]struct{}),
		registeredUsers: make(map[User]struct{}),

		perms2roles: make(map[Role]map[Permission]struct{}),
		roles2users: make(map[User]map[Role]struct{}),

		mutex: new(sync.RWMutex),
	}
}
