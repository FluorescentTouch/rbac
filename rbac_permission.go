package rbac

// RegisterPermission registers new Permission in RBAC controller.
// Returns false if such Permission already registered.
func (r *RBAC) RegisterPermission(p Permission) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredPermissions[p]
	if ok {
		return false
	}
	r.registeredPermissions[p] = struct{}{}
	return true
}


// RemovePermission removes Permission from RBAC controller registered permissions list.
// Will also remove this Permission from all Roles.
// Returns false if no such Permission were registered in controller.
func (r *RBAC) RemovePermission(p Permission) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.registeredPermissions[p]
	if !ok {
		return false
	}

	// removing permission from all roles
	for role, perms := range r.perms2roles {
		if _, ok := perms[p]; ok {
			delete(perms, p)
			r.perms2roles[role] = perms
		}
	}

	delete(r.registeredPermissions, p)
	return true
}

// ListPermissions returns all registered Permissions
func (r *RBAC) ListPermissions() []Permission {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	out := make([]Permission, 0, len(r.registeredPermissions))
	for p := range r.registeredPermissions {
		out = append(out, p)
	}
	return out
}

// PermissionExists checks if Permission is registered in RBAC controller
func (r *RBAC) PermissionExists(p Permission) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.registeredPermissions[p]
	return ok
}

