package rbac

import "sync"


/*
type RBACController interface {
	AddRole(role string) bool
	RemoveRole(role string) bool
	HasPermission(role string, object string, action string) bool
	AddPermissionToRole(role string, object string, action string) bool
	RemovePermissionFromRole(role string, object string, action string) bool
	RemovePermissionsWithObject(object string) bool
	RemovePermissionsWithAction(action string) bool
}
*/
type RBAC struct {
	registeredPermissions map[Permission]struct{}
	registeredRoles map[Role]struct{}
	registeredUsers map[User]struct{}

	perms2roles map[Role]map[Permission]struct{}
	roles2users map[User]map[Role]struct{}

	mutex *sync.RWMutex
}

// NewRBAC creates instance of RBAC
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
