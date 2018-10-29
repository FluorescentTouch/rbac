package rbac

import "testing"

var (
	defaultObjectID = "defaultObjectID"
	defaultActionID = "defaultActionID"
)

func TestNewObject(t *testing.T) {
	o := NewObject(defaultObjectID)

	if string(o) != defaultObjectID {
		t.Errorf("Invalid Object creation: id expected %s, got %s", defaultObjectID, string(o))
	}
}

func TestObjectString(t *testing.T) {
	o := NewObject(defaultObjectID)

	if o.String() != defaultObjectID {
		t.Errorf("Invalid output: expected %s, got %s", defaultObjectID, o.String())
	}
}

func TestNewAction(t *testing.T) {
	a := NewAction(defaultActionID)

	if string(a) != defaultActionID {
		t.Errorf("Invalid Action creation: id expected %s, got %s", defaultActionID, string(a))
	}
}

func TestActionString(t *testing.T) {
	a := NewAction(defaultActionID)

	if a.String() != defaultActionID {
		t.Errorf("Invalid output: expected %s, got %s", defaultActionID, a.String())
	}
}

func TestNewPermission(t *testing.T) {
	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)

	p := NewPermission(o, a)

	if p.object != o {
		t.Errorf("Invalid output: expected object %s, got %s", o, p.object)
	}

	if p.action != a {
		t.Errorf("Invalid output: expected action %s, got %s", a, p.action)
	}
}

func TestPermissionObjectAction(t *testing.T) {
	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)

	p := NewPermission(o, a)

	if p.Object() != o {
		t.Errorf("Invalid output: expected object %s, got %s", o, p.Object())
	}

	if p.Action() != a {
		t.Errorf("Invalid output: expected action %s, got %s", a, p.Action())
	}
}