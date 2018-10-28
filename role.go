package rbac

type Role struct {
	id string
}

func NewRole(id string) Role {
	return Role{id: id}
}

// Name returns Role's name
func (r *Role)ID()string {
	return r.id
}
