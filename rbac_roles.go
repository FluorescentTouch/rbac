package rbac

// RegisterRole registers new Role in RBAC controller.
// Returns false if such Role already registered.
func (rbac *RBAC) RegisterRole(r Role) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredRoles[r]
	if ok {
		return false
	}
	rbac.registeredRoles[r] = struct{}{}
	return true
}

// RemoveRole removes Role from RBAC controller registered roles list.
// Will also remove this Role from all Users.
// Returns false if no such Role were registered in controller.
func (rbac *RBAC) RemoveRole(r Role) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredRoles[r]
	if !ok {
		return false
	}

	// removing Role from all Users
	for user, roles := range rbac.roles2users {
		if _, ok := roles[r]; ok {
			delete(roles, r)
			rbac.roles2users[user] = roles
		}
	}

	delete(rbac.registeredRoles, r)
	return true
}

// ListRoles returns all registered Roles
func (rbac *RBAC) ListRoles() []Role {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	out := make([]Role, 0, len(rbac.registeredRoles))
	for r := range rbac.registeredRoles {
		out = append(out, r)
	}
	return out
}

// RoleExists checks if Role is registered in RBAC controller
func (rbac *RBAC) RoleExists(r Role) bool {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredRoles[r]
	return ok
}

// ListRolePermissions returns all Permissions assigned to Role.
// Role has to be registered.
func (rbac *RBAC) ListRolePermissions(r Role) ([]Permission, error) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredRoles[r]
	if !ok {
		return nil, ErrorRoleNotRegistered
	}
	rolePerms, ok := rbac.perms2roles[r]
	if !ok {
		return []Permission{}, nil
	}
	out := make([]Permission, 0, len(rolePerms))
	for p := range rolePerms {
		out = append(out, p)
	}
	return out, nil
}

// RoleHasPermission checks if Permission is assigned to Role
// Both Role and Permission has to be registered.
func (rbac *RBAC) RoleHasPermission(r Role, p Permission) (bool, error) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredRoles[r]
	if !ok {
		return false, ErrorRoleNotRegistered
	}
	_, ok = rbac.registeredPermissions[p]
	if !ok {
		return false, ErrorPermissionNotRegistered
	}

	_, ok = rbac.perms2roles[r][p]
	return ok, nil
}

// AssignPermissionToRole assigns Permission to Role.
// Both Permission and Role has to be registered.
// Returns false if Permission already assigned to Role.
func (rbac *RBAC) AssignPermissionToRole(r Role, p Permission) (bool, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredRoles[r]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	_, ok = rbac.registeredPermissions[p]
	if !ok {
		return false, ErrorPermissionNotRegistered
	}

	rolePerms, ok := rbac.perms2roles[r]
	if !ok {
		rolePerms = make(map[Permission]struct{})
		rolePerms[p] = struct{}{}
		rbac.perms2roles[r] = rolePerms
		return true, nil
	}
	_, ok = rolePerms[p]
	if ok {
		return false, nil
	}
	rolePerms[p] = struct{}{}
	rbac.perms2roles[r] = rolePerms
	return true, nil
}

// RemovePermissionFromRole removes Permission from Role.
// Both Role and Permission has to be registered.
// Returns false if Permission was not assigned to Role.
func (rbac *RBAC) RemovePermissionFromRole(r Role, p Permission) (bool, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredRoles[r]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	_, ok = rbac.registeredPermissions[p]
	if !ok {
		return false, ErrorPermissionNotRegistered
	}

	_, ok = rbac.perms2roles[r][p]
	if !ok {
		return false, nil
	}

	delete(rbac.perms2roles[r], p)
	return true, nil
}