package rbac

import "sync"

type (
	permission struct {
		object string
		action string
	}
)
type RBACController interface {
	AddRole(role string) bool
	RemoveRole(role string) bool
	HasPermission(role string, object string, action string) bool
	AddPermissionToRole(role string, object string, action string) bool
	RemovePermissionFromRole(role string, object string, action string) bool
	RemovePermissionsWithObject(object string) bool
	RemovePermissionsWithAction(action string) bool
}

type rbacContorller struct {
	mutex *sync.RWMutex
	m     map[string]map[permission]struct{}
}

// NewRBACController creates instance of RBACController
func NewRBACController() RBACController {
	return &rbacContorller{
		mutex: &sync.RWMutex{},
		m:     make(map[string]map[permission]struct{}),
	}
}

func (rbac *rbacContorller) roleExists(role string) bool {
	_, ok := rbac.m[role]
	return ok
}

func (rbac *rbacContorller) rolePermExists(role string, object string, action string) bool {
	if !rbac.roleExists(role) {
		return false
	}
	_, ok := rbac.m[role][permission{object: object, action: action}]
	return ok
}

// AddRole adds new role to model.
// Returns false if role already exists.
func (rbac *rbacContorller) AddRole(role string) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	if rbac.roleExists(role) {
		return false
	}

	rbac.m[role] = make(map[permission]struct{})
	return true
}

// RemoveRole removes role from model.
// Returns false if role was not found.
func (rbac *rbacContorller) RemoveRole(role string) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	if !rbac.roleExists(role) {
		return false
	}

	delete(rbac.m, role)
	return true
}

// HasPermission checks if role has permission with given object and action.
// Will return false if role does not exist in model.
func (rbac *rbacContorller) HasPermission(role string, object string, action string) bool {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	return rbac.rolePermExists(role, object, action)
}

// AddPermissionToRole adds permission with given object and action to string.
// Will create role if no given role presented in model.
// Returns false if such permission were already granted.
func (rbac *rbacContorller) AddPermissionToRole(role string, object string, action string) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	if rbac.rolePermExists(role, object, action) {
		return false
	}

	if !rbac.roleExists(role) {
		rbac.m[role] = make(map[permission]struct{})
	}

	rbac.m[role][permission{object: object, action: action}] = struct{}{}
	return true
}

// RemovePermissionFromRole removes permission with given object and action from role.
// Returns false if no such permission were granted.
func (rbac *rbacContorller) RemovePermissionFromRole(role string, object string, action string) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	if !rbac.rolePermExists(role, object, action) {
		return false
	}

	delete(rbac.m[role], permission{object: object, action: action})
	return true
}

// RemovePermissionsWithObject removes all permission with given object
// Returns false if no permission with such object were presented in model
func (rbac *rbacContorller) RemovePermissionsWithObject(object string) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	var deletedAny bool

	for role, perms := range rbac.m {
		for p := range perms {
			if p.object == object {
				delete(rbac.m[role], p)
				deletedAny = true
			}
		}
	}
	return deletedAny
}

// RemovePermissionsWithAction removes all permission with given action
// Returns false if no permission with such action were presented in model
func (rbac *rbacContorller) RemovePermissionsWithAction(action string) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	var deletedAny bool

	for role, perms := range rbac.m {
		for p := range perms {
			if p.action == action {
				delete(rbac.m[role], p)
				deletedAny = true
			}
		}
	}
	return deletedAny
}
