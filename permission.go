package rbac

type (
	// Object describes object of access control
	Object string
	// Action describes action of access control
	Action string

	// Permission describes unique object-action tuple
	Permission struct {
		object Object
		action Action
	}
)

// NewObject creates Object instance
func NewObject(id string) Object {
	return Object(id)
}

func (o Object)String()string {
	return string(o)
}

// NewAction creates Action instance
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

// Object returns Object property of Permission
func (p Permission)Object()Object{
	return p.object
}

// Action returns Action property of Permission
func (p Permission)Action()Action{
	return p.action
}