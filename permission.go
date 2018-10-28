package rbac

type (
	Object string
	Action string

	Permission struct {
		object Object
		action Action
	}
)

func NewObject(id string) Object {
	return Object(id)
}

func (o Object)String()string {
	return string(o)
}

func NewAction(id string) Action {
	return Action(id)
}

func (a Action)String() string {
	return string(a)
}

// NewPermission returns new permission based on provided Object and Action
func NewPermission(o Object, a Action) Permission {
	return Permission{object:o, action:a}
}

func (p Permission)Object()Object{
	return p.object
}

func (p Permission)Action()Action{
	return p.action
}