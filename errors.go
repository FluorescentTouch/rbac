package rbac

import "errors"

var (
	ErrorPermissionNotRegistered = errors.New("permission is not registered")
	ErrorRoleNotRegistered = errors.New("role is not registered")
	ErrorUserNotRegistered = errors.New("user is not registered")
)
