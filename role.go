package rbac

// Role describes unity of Permissions
type Role struct {
	id string
}

// NewRole returns new Role
func NewRole(id string) Role {
	return Role{id: id}
}

func (r *Role)ID()string {
	return r.id
}
