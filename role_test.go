package rbac

import "testing"

var (
	defaultRoleID = "defaultRoleID"
)

func TestNewRole(t *testing.T) {
	r := NewRole(defaultRoleID)

	if r.id != defaultRoleID {
		t.Errorf("Invalid Role creation: id expected %s, got %s", defaultRoleID, r.id)
	}
}

func TestRoleID(t *testing.T) {
	r := Role{id:defaultRoleID}

	if r.ID() != defaultRoleID {
		t.Errorf("Invalid output: expected %s, got %s", defaultRoleID, r.ID())
	}
}