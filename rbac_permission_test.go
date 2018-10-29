package rbac

import (
	"testing"
	"fmt"
)

func TestRegisterPermission(t *testing.T) {
	rbac := NewRBAC()

	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)

	// case 1: permission is not registered
	ok := rbac.RegisterPermission(p)

	if !ok {
		t.Errorf("[case 1] invalid output: expected %t got %t ", true, ok)
	}

	if _, ok := rbac.registeredPermissions[p]; !ok {
		t.Errorf("[case 1] permission %v not presented in registeredPermissions", p)
	}

	// case 2: permission is registered
	rbac.registeredPermissions[p] = struct{}{}

	ok = rbac.RegisterPermission(p)
	if ok {
		t.Errorf("[case 2] invalid output: expected %t got %t ", false, ok)
	}
}

func TestRemovePermission(t *testing.T) {
	rbac := NewRBAC()

	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)
	r := NewRole(defaultRoleID)

	// case 1: permission is not registered
	exist := rbac.RemovePermission(p)
	if exist {
		t.Errorf("[case 1] invalid output: expected %t got %t ", false, exist)
	}

	// case 2 : permission is registered, no assigning to role
	rbac.registeredPermissions[p] = struct{}{}

	exist = rbac.RemovePermission(p)
	if !exist {
		t.Errorf("[case 2] invalid output: expected %t got %t ", true, exist)
	}

	if _, ok := rbac.registeredPermissions[p]; ok {
		t.Errorf("[case 2] permission were not removed from registered permission list")
	}

	// case 3: permission is registered, assigned to role
	rbac.registeredPermissions[p] = struct{}{}
	rbac.registeredRoles[r] = struct{}{}
	rbac.perms2roles[r] = map[Permission]struct{}{p:struct{}{}}

	exist = rbac.RemovePermission(p)
	if !exist {
		t.Errorf("[case 3] invalid output: expected %t got %t ", true, exist)
	}

	if _, ok := rbac.registeredPermissions[p]; ok {
		t.Errorf("[case 3] permission were not removed from registered permission list")
	}

	if _, ok := rbac.perms2roles[r][p]; ok {
		t.Errorf("[case 3] permission were not unassigned from role")
	}
}

func TestListPermissions(t *testing.T) {
	var (
		objectIDPattern = "Object"
		actionIDPattern = "Action"
	)
	rbac := NewRBAC()
	expectedToFind := make([]Permission, 0, 100)

	for i := 0; i < 100; i++ {
		objectID := fmt.Sprintf("%s%d", objectIDPattern, i)
		o := NewObject(objectID)

		actionID := fmt.Sprintf("%s%d", actionIDPattern, i)
		a := NewAction(actionID)

		p := NewPermission(o, a)

		rbac.RegisterPermission(p)
		expectedToFind = append(expectedToFind, p)
	}

	list := rbac.ListPermissions()

	for _, p := range expectedToFind {
		if !permissionExistsIn(p, list) {
			t.Errorf("invalid output: expected to find %v, got nothing", p)
		}
	}

	if len(expectedToFind) != len(list) {
		t.Errorf("invalid output: expected list len %d, for %d", len(expectedToFind), len(list))
	}
}

func permissionExistsIn(p Permission, list []Permission) bool {
	for _, tmpP := range list {
		if tmpP == p {
			return true
		}
	}
	return false
}

func TestPermissionExists(t *testing.T) {
	rbac := NewRBAC()

	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)

	rbac.RegisterPermission(p)

	if !rbac.PermissionExists(p) {
		t.Errorf("invalid output: expected permission %v to exists, got %t", p, rbac.PermissionExists(p))
	}

	var (
		randomObjectID = "randomObjectID"
		randomActionID = "randomActionID"
	)

	o = NewObject(randomObjectID)
	a = NewAction(randomActionID)
	p = NewPermission(o, a)

	if rbac.PermissionExists(p) {
		t.Errorf("invalid output: expected permission %v to not exists, got %t", p, rbac.PermissionExists(p))
	}
}