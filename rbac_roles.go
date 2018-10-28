package rbac

// RegisterRole registers new Role in RBAC controller.
// Returns false if such Role already registered.
func (r *RBAC) RegisterRole(role Role) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredRoles[role]
	if ok {
		return false
	}
	r.registeredRoles[role] = struct{}{}
	return true
}

// RemoveRole removes Role from RBAC controller registered roles list.
// Will also remove this Role from all Users.
// Returns false if no such Role were registered in controller.
func (r *RBAC) RemoveRole(role Role) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredRoles[role]
	if !ok {
		return false
	}

	// removing Role from all Users
	for user, roles := range r.roles2users {
		if _, ok := roles[role]; ok {
			delete(roles, role)
			r.roles2users[user] = roles
		}
	}

	delete(r.registeredRoles, role)
	return true
}

// ListRoles returns all registered Roles
func (r *RBAC) ListRoles() []Role {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	out := make([]Role, 0, len(r.registeredRoles))
	for role := range r.registeredRoles {
		out = append(out, role)
	}
	return out
}

// RoleExists checks if Role is registered in RBAC controller
func (r *RBAC) RoleExists(role Role) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredRoles[role]
	return ok
}

// ListRolePermissions returns all Permissions assigned to Role.
// Role has to be registered.
func (r *RBAC) ListRolePermissions(role Role) ([]Permission, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredRoles[role]
	if !ok {
		return nil, ErrorRoleNotRegistered
	}
	rolePerms, ok := r.perms2roles[role]
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
func (r *RBAC) RoleHasPermission(role Role, p Permission) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredRoles[role]
	if !ok {
		return false, ErrorRoleNotRegistered
	}
	_, ok = r.registeredPermissions[p]
	if !ok {
		return false, ErrorPermissionNotRegistered
	}

	_, ok = r.perms2roles[role][p]
	return ok, nil
}

// AddRoleToUser assigns Role to User.
// Both User and Role has to be registered.
// Returns false if Role already assigned to User.
func (r *RBAC) AssignRoleToUser(u User, role Role) (bool, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}

	_, ok = r.registeredRoles[role]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	userRoles, ok := r.roles2users[u]
	if !ok {
		userRoles = make(map[Role]struct{})
		userRoles[role] = struct{}{}
		r.roles2users[u] = userRoles
		return true, nil
	}
	_, ok = userRoles[role]
	if ok {
		return false, nil
	}
	userRoles[role] = struct{}{}
	r.roles2users[u] = userRoles
	return true, nil
}

// RemoveRoleFromUser removes Role from User.
// Both User and Role has to be registered.
// Returns false if Role was not assigned to User.
func (r *RBAC) RemoveRoleFromUser(u User, role Role) (bool, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}

	_, ok = r.registeredRoles[role]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	_, ok = r.roles2users[u][role]
	if !ok {
		return false, nil
	}

	delete(r.roles2users[u], role)
	return true, nil
}