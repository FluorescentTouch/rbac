package rbac

import (
	"testing"
	"fmt"
)

func TestRegisterRole(t *testing.T) {
	rbac := NewRBAC()
	r := NewRole(defaultRoleID)

	// case 1: role is not registered
	ok := rbac.RegisterRole(r)

	if !ok {
		t.Errorf("[case 1] invalid output: expected %t got %t ", true, ok)
	}

	if _, ok := rbac.registeredRoles[r]; !ok {
		t.Errorf("[case 1] role %v not presented in registeredRoles", r)
	}

	// case 2: role is registered
	rbac.registeredRoles[r] = struct{}{}

	ok = rbac.RegisterRole(r)
	if ok {
		t.Errorf("[case 2] invalid output: expected %t got %t ", false, ok)
	}
}

func TestRemoveRole(t *testing.T) {
	rbac := NewRBAC()

	r := NewRole(defaultRoleID)
	u := NewUser(defaultUserID)

	// case 1: role is not registered
	exist := rbac.RemoveRole(r)
	if exist {
		t.Errorf("[case 1] invalid output: expected %t got %t ", false, exist)
	}

	// case 2 : role is registered, no assigning to user
	rbac.registeredRoles[r] = struct{}{}

	exist = rbac.RemoveRole(r)
	if !exist {
		t.Errorf("[case 2] invalid output: expected %t got %t ", true, exist)
	}

	if _, ok := rbac.registeredRoles[r]; ok {
		t.Errorf("[case 2] role were not removed from registered role list")
	}

	// case 3: role is registered, assigned to user
	rbac.registeredRoles[r] = struct{}{}
	rbac.registeredUsers[u] = struct{}{}
	rbac.roles2users[u] = map[Role]struct{}{r:{}}

	exist = rbac.RemoveRole(r)
	if !exist {
		t.Errorf("[case 3] invalid output: expected %t got %t ", true, exist)
	}

	if _, ok := rbac.registeredRoles[r]; ok {
		t.Errorf("[case 3] role were not removed from registered role list")
	}

	if _, ok := rbac.roles2users[u][r]; ok {
		t.Errorf("[case 3] role were not unassigned from user")
	}
}

func TestListRoles(t *testing.T) {
	var (
		roleIDPattern = "Role"
	)
	rbac := NewRBAC()
	expectedToFind := make([]Role, 0, 100)

	for i := 0; i < 100; i++ {
		roleID := fmt.Sprintf("%s%d", roleIDPattern, i)
		r := NewRole(roleID)

		rbac.RegisterRole(r)
		expectedToFind = append(expectedToFind, r)
	}

	list := rbac.ListRoles()

	for _, r := range expectedToFind {
		if !roleExistsIn(r, list) {
			t.Errorf("invalid output: expected to find %v, got nothing", r)
		}
	}

	if len(expectedToFind) != len(list) {
		t.Errorf("invalid output: expected list len %d, for %d", len(expectedToFind), len(list))
	}
}

func roleExistsIn(r Role, list []Role) bool {
	for _, tmpP := range list {
		if tmpP == r {
			return true
		}
	}
	return false
}

func TestRoleExists(t *testing.T) {
	rbac := NewRBAC()

	r := NewRole(defaultRoleID)

	rbac.RegisterRole(r)

	if !rbac.RoleExists(r) {
		t.Errorf("invalid output: expected role %v to exists, got %t", r, rbac.RoleExists(r))
	}

	var (
		randomRoleID = "randomRoleID"
	)

	r = NewRole(randomRoleID)

	if rbac.RoleExists(r) {
		t.Errorf("invalid output: expected role %v to not exists, got %t", r, rbac.RoleExists(r))
	}
}

func TestAssignPermissionToRole(t *testing.T) {
	rbac := NewRBAC()

	r := NewRole(defaultRoleID)
	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)

	// case 1: role is not registered
	_, err := rbac.AssignPermissionToRole(r, p)
	if err == nil {
		t.Errorf("[case 1] assign error: expected err equal %v, got nil", ErrorRoleNotRegistered)
	}

	if err != ErrorRoleNotRegistered {
		t.Errorf("[case 1] assign error: expected err equal %v, got %v", ErrorRoleNotRegistered, err)

	}

	// case 2: role is registered, permission is not registered
	rbac.RegisterRole(r)

	_, err = rbac.AssignPermissionToRole(r, p)
	if err == nil {
		t.Errorf("[case 2] assign error: expected err equal %v, got nil", ErrorPermissionNotRegistered)
	}

	if err != ErrorPermissionNotRegistered {
		t.Errorf("[case 2] assign error: expected err equal %v, got %v", ErrorPermissionNotRegistered, err)

	}

	// case 3: role and permission are registered, permission is unassigned to role
	rbac.RegisterRole(r)
	rbac.RegisterPermission(p)

	ok, err := rbac.AssignPermissionToRole(r, p)
	if err != nil {
		t.Errorf("[case 3] assign error: expected err equal nil, got %v", err)
	}

	if !ok {
		t.Errorf("[case 3] invalid output: expected %v, got %v", true, ok)
	}

	if _, ok := rbac.perms2roles[r][p]; !ok {
		t.Errorf("[case 3] assign error: permission were not assigned to role")
	}

	// case 4: role and permission are registered, permission is assigned to role
	rbac.RegisterRole(r)
	rbac.RegisterPermission(p)

	rbac.perms2roles[r]=map[Permission]struct{}{p:{}}

	ok, err = rbac.AssignPermissionToRole(r, p)
	if err != nil {
		t.Errorf("[case 4] assign error: expected err equal nil, got %v", err)
	}

	if ok {
		t.Errorf("[case 4] invalid output: expected %v, got %v", false, ok)
	}
}

func TestListRolePermissions(t *testing.T) {
	var (
		objectIDPattern = "Object"
		actionIDPattern = "Action"
	)
	rbac := NewRBAC()
	r := NewRole(defaultRoleID)

	// case 1: role is not registered
	_, err := rbac.ListRolePermissions(r)
	if err == nil {
		t.Errorf("[case 1] list error: expected err equal %v, got nil", ErrorRoleNotRegistered)
	}

	if err != ErrorRoleNotRegistered {
		t.Errorf("[case 1] list error: expected err equal %v, got %v", ErrorRoleNotRegistered, err)

	}

	// case 2: role is registered, no permission is assigned
	rbac.RegisterRole(r)

	list, err := rbac.ListRolePermissions(r)
	if err != nil {
		t.Errorf("[case 2] list error: expected err equal nil, got %v", err)
	}
	if len(list) > 0 {
		t.Errorf("[case 2] list error: expected zero list lenght, got %d", len(list))
	}

	// case 3: role is registered, assigned 100 permissions
	rbac.RegisterRole(r)
	expectedToFind := make([]Permission, 0, 100)

	for i := 0; i < 100; i++ {
		objectID := fmt.Sprintf("%s%d", objectIDPattern, i)
		o := NewObject(objectID)

		actionID := fmt.Sprintf("%s%d", actionIDPattern, i)
		a := NewAction(actionID)

		p := NewPermission(o, a)

		rbac.RegisterPermission(p)

		rbac.AssignPermissionToRole(r, p)
		expectedToFind = append(expectedToFind, p)
	}

	list, err = rbac.ListRolePermissions(r)
	if err != nil {
		t.Errorf("[case 2] list error: expected err equal nil, got %v", err)
	}

	for _, p := range expectedToFind {
		if !permissionExistsIn(p, list) {
			t.Errorf("invalid output: expected to find %v, got nothing", p)
		}
	}

	if len(expectedToFind) != len(list) {
		t.Errorf("invalid output: expected list len %d, for %d", len(expectedToFind), len(list))
	}
}

func TestRoleHasPermission(t *testing.T) {
	rbac := NewRBAC()

	r:= NewRole(defaultRoleID)
	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)

	// case 1: role is not registered
	_, err := rbac.RoleHasPermission(r, p)
	if err == nil {
		t.Errorf("[case 1] invalid output: expected err equal %v, got nil", ErrorRoleNotRegistered)
	}

	if err != ErrorRoleNotRegistered {
		t.Errorf("[case 1] invalid output: expected err equal %v, got %v", ErrorRoleNotRegistered, err)

	}

	// case 2: role is registered, permission is not registered
	rbac.RegisterRole(r)

	_, err = rbac.RoleHasPermission(r, p)
	if err == nil {
		t.Errorf("[case 2] invalid output: expected err equal %v, got nil", ErrorPermissionNotRegistered)
	}

	if err != ErrorPermissionNotRegistered {
		t.Errorf("[case 2] invalid output: expected err equal %v, got %v", ErrorPermissionNotRegistered, err)

	}

	// case 3: role and permission are registered, permission is not assigned to role
	rbac.RegisterRole(r)
	rbac.RegisterPermission(p)

	ok, err := rbac.RoleHasPermission(r, p)
	if err != nil {
		t.Errorf("[case 3] invalid output: expected err equal nil, got %v", err)
	}

	if ok {
		t.Errorf("[case 3] invalid output: expected %t, got %t", false, ok)
	}

	// case 4: role and permission are registered, permission is assigned to role
	rbac.RegisterRole(r)
	rbac.RegisterPermission(p)
	rbac.AssignPermissionToRole(r, p)

	ok, err = rbac.RoleHasPermission(r, p)
	if err != nil {
		t.Errorf("[case 4] invalid output: expected err equal nil, got %v", err)
	}
	if !ok {
		t.Errorf("[case 4] invalid output: expected %t, got %t", true, ok)
	}
}

func TestRemovePermissionFromRole(t *testing.T) {
	rbac := NewRBAC()

	r:= NewRole(defaultRoleID)
	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)

	// case 1: role is not registered
	_, err := rbac.RemovePermissionFromRole(r, p)
	if err == nil {
		t.Errorf("[case 1] invalid output: expected err equal %v, got nil", ErrorRoleNotRegistered)
	}

	if err != ErrorRoleNotRegistered {
		t.Errorf("[case 1] invalid output: expected err equal %v, got %v", ErrorRoleNotRegistered, err)

	}

	// case 2: role is registered, permission is not registered
	rbac.RegisterRole(r)

	_, err = rbac.RemovePermissionFromRole(r, p)
	if err == nil {
		t.Errorf("[case 2] invalid output: expected err equal %v, got nil", ErrorPermissionNotRegistered)
	}

	if err != ErrorPermissionNotRegistered {
		t.Errorf("[case 2] invalid output: expected err equal %v, got %v", ErrorPermissionNotRegistered, err)

	}

	// case 3: role and permission are registered, permission is not assigned to role
	rbac.RegisterRole(r)
	rbac.RegisterPermission(p)

	ok, err := rbac.RemovePermissionFromRole(r, p)
	if err != nil {
		t.Errorf("[case 3] invalid output: expected err equal nil, got %v", err)
	}

	if ok {
		t.Errorf("[case 3] invalid output: expected %t, got %t", false, ok)
	}

	// case 4: role and permission are registered, permission is assigned to role
	rbac.RegisterRole(r)
	rbac.RegisterPermission(p)
	rbac.AssignPermissionToRole(r, p)

	ok, err = rbac.RemovePermissionFromRole(r, p)
	if err != nil {
		t.Errorf("[case 4] invalid output: expected err equal nil, got %v", err)
	}
	if !ok {
		t.Errorf("[case 4] invalid output: expected %t, got %t", true, ok)
	}

	if _, ok := rbac.perms2roles[r][p]; ok {
		t.Errorf("[case 4] permission is not removed from role")
	}
}