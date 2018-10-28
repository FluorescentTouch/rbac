package rbac

type User struct {
	id string
}

func NewUser(id string) User {
	return User{id: id}
}

func (u User) Name() string {
	return u.id
}