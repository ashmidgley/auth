# Auth0 Wrapper
![Travis (.com) branch](https://img.shields.io/travis/com/ashmidgley/auth/main)
[![Go Report Card](https://goreportcard.com/badge/github.com/ashmidgley/auth)](https://goreportcard.com/report/github.com/ashmidgley/auth0-wrapper)
[![Go Reference](https://pkg.go.dev/badge/github.com/ashmidgley/auth.svg)](https://pkg.go.dev/github.com/ashmidgley/auth)

A package to make it easier to handle Auth0 authorization and check whether a user is valid or has permissions based on API scopes.

## Setup
 - Create [scopes](https://auth0.com/docs/scopes/api-scopes) for your API in Auth0.
 - If using [ValidUser](#valid-user), add a [custom claims rule](https://auth0.com/docs/scopes/sample-use-cases-scopes-and-claims#add-custom-claims-to-a-token) in Auth0 to include your key in the access token returned to the user:
 ```
 function (user, context, callback) {
  context.accessToken['http://example.com/username'] = user.username;
  return callback(null, user, context);
}
 ```
 
## Install
```
go get github.com/ashmidgley/auth
```

## Usage

### JWT Middleware
Use the middleware to enforce authorization on routes:

```
package main

import (
  "net/http"
  
  "github.com/ashmidgley/auth"
  "github.com/geobuff/api/users"
  "github.com/geobuff/api/scores"
  "github.com/gorilla/mux"
)

func main() {
  router := mux.NewRouter()
  jwtMiddleware := auth.GetJwtMiddleware("example_audience", "example_issuer")
  
  router.Handle("/api/users", jwtMiddleware.Handler(users.GetUsers)).Methods("GET")
  router.Handle("/api/scores", jwtMiddleware.Handler(scores.CreateScore)).Methods("POST")
  
  http.ListenAndServe(":8080", router)
}
```

### Has Permission?
Ensure a requester has a specified permission before performing an action:

```
package users

import (
  "fmt"
  "net/http"
  
  "github.com/ashmidgley/auth"
)

var GetUsers = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
  up := auth.UserPermission{
    Request:    request,
    Permission: "read_users",
  }

  if hasPermission, err := auth.HasPermission(up); err != nil {
    http.Error(writer, fmt.Sprintf("%v\n", err), http.StatusInternalServerError)
    return
  } else if !hasPermission {
    http.Error(writer, "invalid permissions to make request", http.StatusUnauthorized)
    return
  }
  
  // User has permission...
})
```

### Valid User?
Confirm the requester is either making changes to their own data or has the correct permission to complete the action. Note that the UserValidation 'Identifier' value below is the same as we specified in our custom claims rule in [Setup](#setup).

```
package scores

import (
  "fmt"
  "net/http"
  
  "github.com/ashmidgley/auth"
)

var CreateScore = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
  user := getUser(request)
  
  uv := auth.UserValidation{
    Request:    request,
    Permission: "write_scores",
    Identifier: "http://example.com/username",
    Key:        user.username,
  }

  if code, err := auth.ValidUser(uv); err != nil {
    http.Error(writer, fmt.Sprintf("%v\n", err), code)
    return
  }

  // User is valid...
})
```
