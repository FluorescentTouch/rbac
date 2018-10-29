package rbac

import "testing"

func TestNewRBAC(t *testing.T) {
	rbac := NewRBAC()

	if rbac.registeredPermissions == nil {
		t.Errorf("controller initialization error: registeredPermissions is nil")
	}

	if rbac.registeredRoles == nil {
		t.Errorf("controller initialization error: registeredRoles is nil")
	}

	if rbac.registeredUsers == nil {
		t.Errorf("controller initialization error: registeredUsers is nil")
	}

	if rbac.perms2roles == nil {
		t.Errorf("controller initialization error: perms2roles is nil")
	}

	if rbac.roles2users == nil {
		t.Errorf("controller initialization error: roles2users is nil")
	}
	
	if rbac.mutex == nil {
		t.Errorf("controller initialization error: mutex is nil")
	}
}
