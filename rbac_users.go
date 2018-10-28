package rbac

// RegisterUser registers new User in RBAC controller.
// Returns false if such User already registered.
func (r *RBAC) RegisterUser(u User) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredUsers[u]
	if ok {
		return false
	}
	r.registeredUsers[u] = struct{}{}
	return true
}

// RemoveUser removes User from RBAC controller registered users list.
// Returns false if no such User were registered in controller.
func (r *RBAC) RemoveUser(u User) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredUsers[u]
	if !ok {
		return false
	}

	delete(r.registeredUsers, u)
	return true
}

// ListUsers returns all registered Users
func (r *RBAC) ListUsers() []User {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	out := make([]User, 0, len(r.registeredUsers))
	for u := range r.registeredUsers {
		out = append(out, u)
	}
	return out
}

// UserExists checks if User is registered in RBAC controller
func (r *RBAC) UserExists(u User) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredUsers[u]
	return ok
}

// ListUserRoles returns all Roles assigned to User.
// User has to be registered.
func (r *RBAC) ListUserRoles(u User) ([]Role, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredUsers[u]
	if !ok {
		return nil, ErrorUserNotRegistered
	}
	userRoles, ok := r.roles2users[u]
	if !ok {
		return []Role{}, nil
	}
	out := make([]Role, 0, len(userRoles))
	for role := range userRoles {
		out = append(out, role)
	}
	return out, nil
}

// UserHasRole checks if Role is assigned to User
// Both User and Role has to be registered.
func (r *RBAC) UserHasRole(u User, role Role) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}
	_, ok = r.registeredRoles[role]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	_, ok = r.roles2users[u][role]
	return ok, nil
}

// UserHasPermission checks if any assigned to User Role has provided Permission.
// Both User and Permission has to be registered.
func (r *RBAC) UserHasPermission(u User, p Permission) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}

	userRoles := r.roles2users[u]
	for role := range userRoles {
		_, ok := r.perms2roles[role][p]
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// UserHasPermission checks if any assigned to User Role has Permission with provided Object and Action.
// Both User and Permission with provided Object and Action has to be registered.
func (r *RBAC) UserHasObjectAction(u User, o Object, a Action) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	p := NewPermission(o, a)
	_, ok := r.registeredPermissions[p]
	if !ok {
		return false, ErrorPermissionNotRegistered
	}

	return r.UserHasPermission(u, p)
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