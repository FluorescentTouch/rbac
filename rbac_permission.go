package rbac

// RegisterPermission registers new Permission in RBAC controller.
// Returns false if such Permission already registered.
func (rbac *RBAC) RegisterPermission(p Permission) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredPermissions[p]
	if ok {
		return false
	}
	rbac.registeredPermissions[p] = struct{}{}
	return true
}


// RemovePermission removes Permission from RBAC controller registered permissions list.
// Will also remove this Permission from all Roles.
// Returns false if no such Permission were registered in controller.
func (rbac *RBAC) RemovePermission(p Permission) bool {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	_, ok := rbac.registeredPermissions[p]
	if !ok {
		return false
	}

	// removing permission from all roles
	for r, perms := range rbac.perms2roles {
		if _, ok := perms[p]; ok {
			delete(perms, p)
			rbac.perms2roles[r] = perms
		}
	}

	delete(rbac.registeredPermissions, p)
	return true
}

// ListPermissions returns all registered Permissions
func (rbac *RBAC) ListPermissions() []Permission {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	out := make([]Permission, 0, len(rbac.registeredPermissions))
	for p := range rbac.registeredPermissions {
		out = append(out, p)
	}
	return out
}

// PermissionExists checks if Permission is registered in RBAC controller
func (rbac *RBAC) PermissionExists(p Permission) bool {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	_, ok := rbac.registeredPermissions[p]
	return ok
}

