package rbac

// User describes unity of Roles
type User struct {
	id string
}

// NewUser creates new User
func NewUser(id string) User {
	return User{id: id}
}

func (u User) ID() string {
	return u.id
}