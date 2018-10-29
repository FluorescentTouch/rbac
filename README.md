RBAC controller
-------------------

Simple controller, that operates Users, Roles and Permissions (combined from Object and Action).

### How to start

Just create new Users, Roles, Objects and Action via embeded functions and for Users, Roles and Permission - dont forget to Register them in controller first.

### Sample example


    package main
    
    import (
	    "rbac"
	    "fmt"
    )
  
    func main() {
	  controller := rbac.NewRBAC()
  
	  user := rbac.NewUser("userID")
	  controller.RegisterUser(user)
  
	  role := rbac.NewRole("roleID")
	  controller.RegisterRole(role)
  
	  object := rbac.NewObject("resourceID")
	  action := rbac.NewAction("operationID")
	  permission := rbac.NewPermission(object, action)
	  controller.RegisterPermission(permission)

	  _, err := controller.AssignPermissionToRole(role, permission)
	  if err != nil {
		  panic(err)
	  }
  
	  _, err = controller.AssignRoleToUser(user, role)
	  if err != nil {
		  panic(err)
	  }
  
	  // check if user has required permission
	  ok, err := controller.UserHasPermission(user, permission)
	  if err != nil {
		  panic(err)
	  }
	  fmt.Printf("User has permission to %s %s: %t\n", permission.Object(), permission.Action(), ok)
  
	  // another way to check if user has required permission
	  ok, err = controller.UserHasObjectAction(user, object, action)
	  if err != nil {
		  panic(err)
	  }
	  fmt.Printf("User has permission to %s %s: %t\n", object, action, ok)
    }
