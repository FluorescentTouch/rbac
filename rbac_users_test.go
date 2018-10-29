package rbac

import (
	"testing"
	"fmt"
)

func TestRegisterUser(t *testing.T) {
	rbac := NewRBAC()
	u := NewUser(defaultUserID)

	// case 1: user is not registered
	ok := rbac.RegisterUser(u)

	if !ok {
		t.Errorf("[case 1] invalid output: expected %t got %t ", true, ok)
	}

	if _, ok := rbac.registeredUsers[u]; !ok {
		t.Errorf("[case 1] user %v not presented in registeredUsers", u)
	}

	// case 2: user is registered
	rbac.registeredUsers[u] = struct{}{}

	ok = rbac.RegisterUser(u)
	if ok {
		t.Errorf("[case 2] invalid output: expected %t got %t ", false, ok)
	}
}

func TestRemoveUser(t *testing.T) {
	rbac := NewRBAC()

	r := NewRole(defaultRoleID)
	u := NewUser(defaultUserID)

	// case 1: user is not registered
	exist := rbac.RemoveUser(u)
	if exist {
		t.Errorf("[case 1] invalid output: expected %t got %t ", false, exist)
	}

	// case 2 : user is registered, no roles assigned
	rbac.registeredUsers[u] = struct{}{}

	exist = rbac.RemoveUser(u)
	if !exist {
		t.Errorf("[case 2] invalid output: expected %t got %t ", true, exist)
	}

	if _, ok := rbac.registeredUsers[u]; ok {
		t.Errorf("[case 2] user were not removed from registered user list")
	}

	// case 3: user is registered, role is assigned
	rbac.registeredUsers[u] = struct{}{}
	rbac.registeredRoles[r] = struct{}{}
	rbac.roles2users[u] = map[Role]struct{}{r:{}}

	exist = rbac.RemoveUser(u)
	if !exist {
		t.Errorf("[case 3] invalid output: expected %t got %t ", true, exist)
	}

	if _, ok := rbac.registeredUsers[u]; ok {
		t.Errorf("[case 3] user were not removed from registered user list")
	}

	if _, ok := rbac.roles2users[u][r]; ok {
		t.Errorf("[case 3] roles were not unassigned from user")
	}
}

func TestListUsers(t *testing.T) {
	var (
		userIDPattern = "User"
	)
	rbac := NewRBAC()
	expectedToFind := make([]User, 0, 100)

	for i := 0; i < 100; i++ {
		roleID := fmt.Sprintf("%s%d", userIDPattern, i)
		u := NewUser(roleID)

		rbac.RegisterUser(u)
		expectedToFind = append(expectedToFind, u)
	}

	list := rbac.ListUsers()

	for _, u := range expectedToFind {
		if !userExistsIn(u, list) {
			t.Errorf("invalid output: expected to find %v, got nothing", u)
		}
	}

	if len(expectedToFind) != len(list) {
		t.Errorf("invalid output: expected list len %d, for %d", len(expectedToFind), len(list))
	}
}

func userExistsIn(u User, list []User) bool {
	for _, tmpP := range list {
		if tmpP == u {
			return true
		}
	}
	return false
}

func TestUserExists(t *testing.T) {
	rbac := NewRBAC()

	u := NewUser(defaultUserID)

	rbac.RegisterUser(u)

	if !rbac.UserExists(u) {
		t.Errorf("invalid output: expected user %v to exists, got %t", u, rbac.UserExists(u))
	}

	var (
		randomUserID = "randomUserID"
	)

	u = NewUser(randomUserID)

	if rbac.UserExists(u) {
		t.Errorf("invalid output: expected user %v to not exists, got %t", u, rbac.UserExists(u))
	}
}

func TestAssignRoleToUser(t *testing.T) {
	rbac := NewRBAC()

	u := NewUser(defaultUserID)
	r := NewRole(defaultRoleID)

	// case 1: user is not registered
	_, err := rbac.AssignRoleToUser(u, r)
	if err == nil {
		t.Errorf("[case 1] assign error: expected err equal %v, got nil", ErrorUserNotRegistered)
	}

	if err != ErrorUserNotRegistered {
		t.Errorf("[case 1] assign error: expected err equal %v, got %v", ErrorUserNotRegistered, err)

	}

	// case 2: user is registered, role is not registered
	rbac.RegisterUser(u)

	_, err = rbac.AssignRoleToUser(u, r)
	if err == nil {
		t.Errorf("[case 2] assign error: expected err equal %v, got nil", ErrorRoleNotRegistered)
	}

	if err != ErrorRoleNotRegistered {
		t.Errorf("[case 2] assign error: expected err equal %v, got %v", ErrorRoleNotRegistered, err)

	}

	// case 3: user and role are registered, role is not assigned to user
	rbac.RegisterUser(u)
	rbac.RegisterRole(r)

	ok, err := rbac.AssignRoleToUser(u, r)
	if err != nil {
		t.Errorf("[case 3] assign error: expected err equal nil, got %v", err)
	}

	if !ok {
		t.Errorf("[case 3] invalid output: expected %v, got %v", true, ok)
	}

	if _, ok := rbac.roles2users[u][r]; !ok {
		t.Errorf("[case 3] assign error: role were not assigned to user")
	}

	// case 4: user and role are registered, role is assigned to user
	rbac.RegisterUser(u)
	rbac.RegisterRole(r)

	rbac.roles2users[u]=map[Role]struct{}{r:{}}

	ok, err = rbac.AssignRoleToUser(u, r)
	if err != nil {
		t.Errorf("[case 4] assign error: expected err equal nil, got %v", err)
	}

	if ok {
		t.Errorf("[case 4] invalid output: expected %v, got %v", false, ok)
	}
}

func TestListUserRoles(t *testing.T) {
	var (
		roleIDPattern = "Role"
	)
	rbac := NewRBAC()
	u := NewUser(defaultUserID)

	// case 1: user is not registered
	_, err := rbac.ListUserRoles(u)
	if err == nil {
		t.Errorf("[case 1] list error: expected err equal %v, got nil", ErrorUserNotRegistered)
	}

	if err != ErrorUserNotRegistered {
		t.Errorf("[case 1] list error: expected err equal %v, got %v", ErrorUserNotRegistered, err)

	}

	// case 2: user is registered, no role is assigned
	rbac.RegisterUser(u)

	list, err := rbac.ListUserRoles(u)
	if err != nil {
		t.Errorf("[case 2] list error: expected err equal nil, got %v", err)
	}
	if len(list) > 0 {
		t.Errorf("[case 2] list error: expected zero list lenght, got %d", len(list))
	}

	// case 3: user is registered, assigned 100 roles
	rbac.RegisterUser(u)
	expectedToFind := make([]Role, 0, 100)

	for i := 0; i < 100; i++ {
		roleID := fmt.Sprintf("%s%d", roleIDPattern, i)
		r := NewRole(roleID)

		rbac.RegisterRole(r)

		rbac.AssignRoleToUser(u, r)
		expectedToFind = append(expectedToFind, r)
	}

	list, err = rbac.ListUserRoles(u)
	if err != nil {
		t.Errorf("[case 2] list error: expected err equal nil, got %v", err)
	}

	for _, p := range expectedToFind {
		if !roleExistsIn(p, list) {
			t.Errorf("invalid output: expected to find %v, got nothing", p)
		}
	}

	if len(expectedToFind) != len(list) {
		t.Errorf("invalid output: expected list len %d, for %d", len(expectedToFind), len(list))
	}
}

func TestUserHasRole(t *testing.T) {
	rbac := NewRBAC()

	u:= NewUser(defaultUserID)
	r := NewRole(defaultRoleID)

	// case 1: user is not registered
	_, err := rbac.UserHasRole(u, r)
	if err == nil {
		t.Errorf("[case 1] invalid output: expected err equal %v, got nil", ErrorUserNotRegistered)
	}

	if err != ErrorUserNotRegistered {
		t.Errorf("[case 1] invalid output: expected err equal %v, got %v", ErrorUserNotRegistered, err)

	}

	// case 2: user is registered, role is not registered
	rbac.RegisterUser(u)

	_, err = rbac.UserHasRole(u, r)
	if err == nil {
		t.Errorf("[case 2] invalid output: expected err equal %v, got nil", ErrorRoleNotRegistered)
	}

	if err != ErrorRoleNotRegistered {
		t.Errorf("[case 2] invalid output: expected err equal %v, got %v", ErrorRoleNotRegistered, err)

	}

	// case 3: user and role are registered, role is not assigned to user
	rbac.RegisterUser(u)
	rbac.RegisterRole(r)

	ok, err := rbac.UserHasRole(u, r)
	if err != nil {
		t.Errorf("[case 3] invalid output: expected err equal nil, got %v", err)
	}

	if ok {
		t.Errorf("[case 3] invalid output: expected %t, got %t", false, ok)
	}

	// case 4: user and role are registered, role is assigned to user
	rbac.RegisterUser(u)
	rbac.RegisterRole(r)
	rbac.AssignRoleToUser(u, r)

	ok, err = rbac.UserHasRole(u, r)
	if err != nil {
		t.Errorf("[case 4] invalid output: expected err equal nil, got %v", err)
	}
	if !ok {
		t.Errorf("[case 4] invalid output: expected %t, got %t", true, ok)
	}
}

func TestUserHasPermission(t *testing.T) {
	rbac := NewRBAC()

	u := NewUser(defaultUserID)
	r := NewRole(defaultRoleID)
	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)

	// case 1: user is not registered
	_, err := rbac.UserHasPermission(u, p)
	if err == nil {
		t.Errorf("[case 1] invalid output: expected err equal %v, got nil", ErrorUserNotRegistered)
	}

	if err != ErrorUserNotRegistered {
		t.Errorf("[case 1] invalid output: expected err equal %v, got %v", ErrorUserNotRegistered, err)

	}

	// case 2: permission is not registered
	rbac.RegisterUser(u)

	_, err = rbac.UserHasPermission(u, p)
	if err == nil {
		t.Errorf("[case 2] invalid output: expected err equal %v, got nil", ErrorPermissionNotRegistered)
	}

	if err != ErrorPermissionNotRegistered {
		t.Errorf("[case 2] invalid output: expected err equal %v, got %v", ErrorPermissionNotRegistered, err)

	}

	// case 3: user is registered, has no roles with defined permission
	rbac.RegisterUser(u)
	rbac.RegisterPermission(p)
	rbac.RegisterRole(r)
	rbac.AssignRoleToUser(u, r)

	ok, err := rbac.UserHasPermission(u, p)
	if err != nil {
		t.Errorf("[case 3] invalid output: expected err equal nil, got %v", err)
	}
	if ok {
		t.Errorf("[case 3] invalid output: expected %t, got %t", false, ok)
	}

	// case 4: user and role are registered, role is assigned to user, role has required permission
	rbac.RegisterUser(u)
	rbac.RegisterPermission(p)
	rbac.RegisterRole(r)
	rbac.AssignRoleToUser(u, r)
	rbac.AssignPermissionToRole(r, p)

	ok, err = rbac.UserHasPermission(u, p)
	if err != nil {
		t.Errorf("[case 4] invalid output: expected err equal nil, got %v", err)
	}
	if !ok {
		t.Errorf("[case 4] invalid output: expected %t, got %t", true, ok)
	}
}

func TestUserHasObjectAction(t *testing.T) {
	rbac := NewRBAC()

	u := NewUser(defaultUserID)
	r := NewRole(defaultRoleID)
	o := NewObject(defaultObjectID)
	a := NewAction(defaultActionID)
	p := NewPermission(o, a)

	// case 1: user is not registered
	_, err := rbac.UserHasObjectAction(u, o, a)
	if err == nil {
		t.Errorf("[case 1] invalid output: expected err equal %v, got nil", ErrorUserNotRegistered)
	}

	if err != ErrorUserNotRegistered {
		t.Errorf("[case 1] invalid output: expected err equal %v, got %v", ErrorUserNotRegistered, err)

	}

	// case 2: permission with provided object and action is not registered
	rbac.RegisterUser(u)

	_, err = rbac.UserHasObjectAction(u, o, a)
	if err == nil {
		t.Errorf("[case 2] invalid output: expected err equal %v, got nil", ErrorPermissionNotRegistered)
	}

	if err != ErrorPermissionNotRegistered {
		t.Errorf("[case 2] invalid output: expected err equal %v, got %v", ErrorPermissionNotRegistered, err)

	}

	// case 3: user is registered, has no roles with defined object and action
	rbac.RegisterUser(u)
	rbac.RegisterPermission(p)
	rbac.RegisterRole(r)
	rbac.AssignRoleToUser(u, r)

	ok, err := rbac.UserHasObjectAction(u, o, a)
	if err != nil {
		t.Errorf("[case 3] invalid output: expected err equal nil, got %v", err)
	}
	if ok {
		t.Errorf("[case 3] invalid output: expected %t, got %t", false, ok)
	}

	// case 4: user and role are registered, role is assigned to user, role has required permission
	rbac.RegisterUser(u)
	rbac.RegisterPermission(p)
	rbac.RegisterRole(r)
	rbac.AssignRoleToUser(u, r)
	rbac.AssignPermissionToRole(r, p)

	ok, err = rbac.UserHasObjectAction(u, o, a)
	if err != nil {
		t.Errorf("[case 4] invalid output: expected err equal nil, got %v", err)
	}
	if !ok {
		t.Errorf("[case 4] invalid output: expected %t, got %t", true, ok)
	}
}


func TestRemoveRoleFromUser(t *testing.T) {
	rbac := NewRBAC()

	u:= NewUser(defaultUserID)
	r := NewRole(defaultRoleID)

	// case 1: user is not registered
	_, err := rbac.RemoveRoleFromUser(u, r)
	if err == nil {
		t.Errorf("[case 1] invalid output: expected err equal %v, got nil", ErrorUserNotRegistered)
	}

	if err != ErrorUserNotRegistered {
		t.Errorf("[case 1] invalid output: expected err equal %v, got %v", ErrorUserNotRegistered, err)

	}

	// case 2: user is registered, role is not registered
	rbac.RegisterUser(u)

	_, err = rbac.RemoveRoleFromUser(u, r)
	if err == nil {
		t.Errorf("[case 2] invalid output: expected err equal %v, got nil", ErrorRoleNotRegistered)
	}

	if err != ErrorRoleNotRegistered {
		t.Errorf("[case 2] invalid output: expected err equal %v, got %v", ErrorRoleNotRegistered, err)

	}

	// case 3: user and role are registered, role is not assigned to user
	rbac.RegisterUser(u)
	rbac.RegisterRole(r)

	ok, err := rbac.RemoveRoleFromUser(u, r)
	if err != nil {
		t.Errorf("[case 3] invalid output: expected err equal nil, got %v", err)
	}

	if ok {
		t.Errorf("[case 3] invalid output: expected %t, got %t", false, ok)
	}

	// case 4: user and role are registered, role is assigned to user
	rbac.RegisterUser(u)
	rbac.RegisterRole(r)
	rbac.AssignRoleToUser(u, r)

	ok, err = rbac.RemoveRoleFromUser(u, r)
	if err != nil {
		t.Errorf("[case 4] invalid output: expected err equal nil, got %v", err)
	}
	if !ok {
		t.Errorf("[case 4] invalid output: expected %t, got %t", true, ok)
	}

	if _, ok := rbac.roles2users[u][r]; ok {
		t.Errorf("[case 4] role is not removed from user")
	}
}