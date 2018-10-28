package rbac

import "testing"

var (
	defaultUserID = "defaultUserID"
)

func TestNewUser(t *testing.T) {
	u := NewUser(defaultUserID)
	if u.id != defaultUserID {
		t.Errorf("Invalid User creation: id expected %s, got %s", defaultUserID, u.id)
	}
}

func TestUserID(t *testing.T) {
	u := User{id:defaultUserID}

	if u.ID() != defaultUserID {
		t.Errorf("Invalid output: expected %s, got %s", defaultUserID, u.ID())
	}
}
