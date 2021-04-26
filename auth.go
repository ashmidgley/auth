package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
)

// Response holds the response message.
type Response struct {
	Message string `json:"message"`
}

// Jwks holds a list of json web keys.
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys holds fields related to the JSON Web Key Set for this API.
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// UserPermission is the data used in HasPermission.
type UserPermission struct {
	Request    *http.Request
	Permission string
}

// UserValidation is the data used in ValidUser.
type UserValidation struct {
	Request    *http.Request
	Permission string
	Identifier string
	Key        string
}

// GetJwtMiddleware returns the Auth0 middleware used to handle authorized endpoints.
func GetJwtMiddleware(audience, issuer string) *jwtmiddleware.JWTMiddleware {
	return jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			aud := token.Claims.(jwt.MapClaims)["aud"].([]interface{})

			s := make([]string, len(aud))
			for i, v := range aud {
				s[i] = fmt.Sprint(v)
			}
			token.Claims.(jwt.MapClaims)["aud"] = s

			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(audience, false)
			if !checkAud {
				return token, errors.New("Invalid audience")
			}

			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := getPemCert(token, issuer)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})
}

func getPemCert(token *jwt.Token, issuer string) (string, error) {
	cert := ""
	resp, err := http.Get(fmt.Sprintf("%s.well-known/jwks.json", issuer))

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}

// HasPermission confirms the requester has the correct permission to complete the action.
var HasPermission = func(up UserPermission) (bool, error) {
	permissions, err := getPermissions(up.Request)
	if err != nil {
		return false, err
	}
	return permissionPresent(permissions, up.Permission), nil
}

// ValidUser confirms the requester is either making changes to their own data or has the correct permission to complete the action.
var ValidUser = func(uv UserValidation) (int, error) {
	if matchingUser, err := matchingUser(uv.Request, uv.Identifier, uv.Key); err != nil {
		return http.StatusInternalServerError, err
	} else if !matchingUser {
		up := UserPermission{
			Request:    uv.Request,
			Permission: uv.Permission,
		}

		if hasPermission, err := HasPermission(up); err != nil {
			return http.StatusInternalServerError, err
		} else if !hasPermission {
			return http.StatusUnauthorized, errors.New("missing or invalid permissions")
		}
	}

	return 200, nil
}

func getPermissions(request *http.Request) ([]interface{}, error) {
	token, _, err := parseToken(request)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims["permissions"].([]interface{}), nil
	}
	return nil, errors.New("failed to parse claims from token")
}

func parseToken(request *http.Request) (*jwt.Token, []string, error) {
	header := request.Header.Get("Authorization")
	if len(header) < 8 {
		return nil, nil, errors.New("token missing or invalid length")
	}

	tokenString := header[7:]
	parser := new(jwt.Parser)
	return parser.ParseUnverified(tokenString, jwt.MapClaims{})
}

func permissionPresent(permissions []interface{}, target string) bool {
	for _, permission := range permissions {
		if permission == target {
			return true
		}
	}
	return false
}

var matchingUser = func(request *http.Request, identifier string, target string) (bool, error) {
	identifier, err := getIdentifier(request, identifier)
	if err != nil {
		return false, err
	}
	return identifier == target, nil
}

func getIdentifier(request *http.Request, identifier string) (string, error) {
	token, _, err := parseToken(request)
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return fmt.Sprint(claims[identifier]), nil
	}
	return "", errors.New("failed to parse claims from token")
}
