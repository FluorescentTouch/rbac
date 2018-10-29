package rbac

// RegisterUser registers new User in RBAC controller.
// Returns false if such User already registered.
func (rbac *RBAC) RegisterUser(u User) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredUsers[u]
	if ok {
		return false
	}
	rbac.registeredUsers[u] = struct{}{}
	return true
}

// RemoveUser removes User from RBAC controller registered users list.
// Returns false if no such User were registered in controller.
func (rbac *RBAC) RemoveUser(u User) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredUsers[u]
	if !ok {
		return false
	}

	delete(rbac.roles2users, u)

	delete(rbac.registeredUsers, u)
	return true
}

// ListUsers returns all registered Users
func (rbac *RBAC) ListUsers() []User {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	out := make([]User, 0, len(rbac.registeredUsers))
	for u := range rbac.registeredUsers {
		out = append(out, u)
	}
	return out
}

// UserExists checks if User is registered in RBAC controller
func (rbac *RBAC) UserExists(u User) bool {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredUsers[u]
	return ok
}

// ListUserRoles returns all Roles assigned to User.
// User has to be registered.
func (rbac *RBAC) ListUserRoles(u User) ([]Role, error) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredUsers[u]
	if !ok {
		return nil, ErrorUserNotRegistered
	}
	userRoles, ok := rbac.roles2users[u]
	if !ok {
		return []Role{}, nil
	}
	out := make([]Role, 0, len(userRoles))
	for r := range userRoles {
		out = append(out, r)
	}
	return out, nil
}

// UserHasRole checks if Role is assigned to User
// Both User and Role has to be registered.
func (rbac *RBAC) UserHasRole(u User, r Role) (bool, error) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}
	_, ok = rbac.registeredRoles[r]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	_, ok = rbac.roles2users[u][r]
	return ok, nil
}

// UserHasPermission checks if any assigned to User Role has provided Permission.
// Both User and Permission has to be registered.
func (rbac *RBAC) UserHasPermission(u User, p Permission) (bool, error) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}

	_, ok = rbac.registeredPermissions[p]
	if !ok {
		return false, ErrorPermissionNotRegistered
	}

	userRoles := rbac.roles2users[u]
	for r := range userRoles {
		_, ok := rbac.perms2roles[r][p]
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// UserHasPermission checks if any assigned to User Role has Permission with provided Object and Action.
// Both User and Permission with provided Object and Action has to be registered.
func (rbac *RBAC) UserHasObjectAction(u User, o Object, a Action) (bool, error) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	p := NewPermission(o, a)

	return rbac.UserHasPermission(u, p)
}

// AssignRoleToUser assigns Role to User.
// Both User and Role has to be registered.
// Returns false if Role already assigned to User.
func (rbac *RBAC) AssignRoleToUser(u User, r Role) (bool, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}

	_, ok = rbac.registeredRoles[r]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	userRoles, ok := rbac.roles2users[u]
	if !ok {
		userRoles = make(map[Role]struct{})
		userRoles[r] = struct{}{}
		rbac.roles2users[u] = userRoles
		return true, nil
	}
	_, ok = userRoles[r]
	if ok {
		return false, nil
	}
	userRoles[r] = struct{}{}
	rbac.roles2users[u] = userRoles
	return true, nil
}

// RemoveRoleFromUser removes Role from User.
// Both User and Role has to be registered.
// Returns false if Role was not assigned to User.
func (rbac *RBAC) RemoveRoleFromUser(u User, r Role) (bool, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredUsers[u]
	if !ok {
		return false, ErrorUserNotRegistered
	}

	_, ok = rbac.registeredRoles[r]
	if !ok {
		return false, ErrorRoleNotRegistered
	}

	_, ok = rbac.roles2users[u][r]
	if !ok {
		return false, nil
	}

	delete(rbac.roles2users[u], r)
	return true, nil
}