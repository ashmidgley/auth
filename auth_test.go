package auth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestHasPermission(t *testing.T) {
	tt := []struct {
		name       string
		token      string
		permission string
		want       bool
		err        string
	}{
		{
			name:       "invalid token",
			token:      "",
			permission: "read:scores",
			want:       false,
			err:        "token missing or invalid length",
		},
		{
			name:       "valid token, missing permission",
			token:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InpuNmd6ZnBxZDRZbU5hMUZabzFTSiJ9.eyJodHRwOi8vZ2VvYnVmZi5jb20vdXNlcm5hbWUiOiJtcnNjcnViIiwiaXNzIjoiaHR0cHM6Ly9kZXYtZ2VvYnVmZi5hdS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWZjNmM5YWRiMTBkNmQwMDZmNjEwNTk2IiwiYXVkIjpbImh0dHBzOi8vZGV2LWdlb2J1ZmYtYXBpLmNvbSIsImh0dHBzOi8vZGV2LWdlb2J1ZmYuYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTYwODc5NzM5MSwiZXhwIjoxNjA4ODgzNzkxLCJhenAiOiJpUXRrTmc2cHYwZzhsQXFFQUprUkpxMjFONzNzaG9UMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6WyJyZWFkOnVzZXJzIiwid3JpdGU6bGVhZGVyYm9hcmQiLCJ3cml0ZTpzY29yZXMiLCJ3cml0ZTp1c2VycyJdfQ.McI54hJHhMKBoonfCmX4lXScRkK2fxPa4Ej_QkkV_12bzTGeFmtvQsGYnYsnOOZSwRsdsG5JvA2c39l4IQU_7DjY4OFkgSuJnrLfQsInfm4799uefYkpx_ELdbClLSitNAZMObM85iYc_tUZwpI5Yas5stnmUAgf6YJMG_cQVWiVnQZ-9lRhXXdrLjxwdJgtK5MS0YHMSsgZE8QmB3SPZysGx5ICqFshqcKEOmre3LdEwk1jFw0JHLROAPcwQF7D1Ba45XHnZnODxS1xLmpWevdMISHyuXaHDDDVRy_JQCk5C8A1bFsULBilclCDWnGcyGNzNLXBZkVvun9-5JTm6g",
			permission: "read:scores",
			want:       false,
			err:        "",
		},
		{
			name:       "happy path",
			token:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InpuNmd6ZnBxZDRZbU5hMUZabzFTSiJ9.eyJodHRwOi8vZ2VvYnVmZi5jb20vdXNlcm5hbWUiOiJtcnNjcnViIiwiaXNzIjoiaHR0cHM6Ly9kZXYtZ2VvYnVmZi5hdS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWZjNmM5YWRiMTBkNmQwMDZmNjEwNTk2IiwiYXVkIjpbImh0dHBzOi8vZGV2LWdlb2J1ZmYtYXBpLmNvbSIsImh0dHBzOi8vZGV2LWdlb2J1ZmYuYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTYwODc5Njk5NiwiZXhwIjoxNjA4ODgzMzk2LCJhenAiOiJpUXRrTmc2cHYwZzhsQXFFQUprUkpxMjFONzNzaG9UMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6WyJyZWFkOnNjb3JlcyIsInJlYWQ6dXNlcnMiLCJ3cml0ZTpsZWFkZXJib2FyZCIsIndyaXRlOnNjb3JlcyIsIndyaXRlOnVzZXJzIl19.YyQUeX1ttxPF2CUGOlE9m3dBBbi8kDbFXq7-2dld3YPctHJb_wgRxc10RFcyryLkSOdbWFdELoF0sDRh2miEYchdrit7Ac0rTufWkn7pfv4SV8e9yYmlCV-cVBtDjKPDQP2e7TDSuoXOOVBcbdlhyro524bEqAibzWPqfh5apn1HeP_tvbHqdZRdrRZOVu1W89f7uaoua9-DmBASSgeO3KixLYREHAPAI2kFgt2YmWZ-Y_474A2KoIAJgwrbhG094sbDiBuuhRRl2GUURLqbxRB0gIRS1ut4J2DGvkr59t5ev789XIWc4zI3rHvBLJ0hGDyi66Ip8TZW3D-pkNCl6Q",
			permission: "read:scores",
			want:       true,
			err:        "",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest("GET", "", nil)
			if err != nil {
				t.Errorf("error creating request: %v", err)
			}
			request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tc.token))

			up := UserPermission{
				Request:    request,
				Permission: tc.permission,
			}

			result, err := HasPermission(up)
			if err != nil {
				if err.Error() != tc.err {
					t.Fatalf("expected error %v; got %v", tc.err, err.Error())
				}
			} else if tc.err != "" {
				t.Fatalf("expected error %v; got nil", tc.err)
			}

			if result != tc.want {
				t.Fatalf("got %v; want %v", result, tc.want)
			}
		})
	}
}

func TestValidUser(t *testing.T) {
	savedMatchingUser := matchingUser
	savedHasPermission := HasPermission

	defer func() {
		matchingUser = savedMatchingUser
		HasPermission = savedHasPermission
	}()

	tt := []struct {
		name          string
		matchingUser  func(request *http.Request, identifier string, target string) (bool, error)
		hasPermission func(up UserPermission) (bool, error)
		token         string
		username      string
		permission    string
		want          int
		err           string
	}{
		{
			name: "error calling matchingUser",
			matchingUser: func(request *http.Request, identifier string, target string) (bool, error) {
				return false, errors.New("test")
			},
			hasPermission: HasPermission,
			token:         "",
			username:      "mrscrub",
			permission:    "",
			want:          http.StatusInternalServerError,
			err:           "test",
		},
		{
			name:          "error calling HasPermission",
			matchingUser:  matchingUser,
			hasPermission: func(up UserPermission) (bool, error) { return false, errors.New("test") },
			token:         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InpuNmd6ZnBxZDRZbU5hMUZabzFTSiJ9.eyJodHRwOi8vZ2VvYnVmZi5jb20vdXNlcm5hbWUiOiJtcnNjcnViIiwiaXNzIjoiaHR0cHM6Ly9kZXYtZ2VvYnVmZi5hdS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWZjNmM5YWRiMTBkNmQwMDZmNjEwNTk2IiwiYXVkIjpbImh0dHBzOi8vZGV2LWdlb2J1ZmYtYXBpLmNvbSIsImh0dHBzOi8vZGV2LWdlb2J1ZmYuYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTYwODc5Njk5NiwiZXhwIjoxNjA4ODgzMzk2LCJhenAiOiJpUXRrTmc2cHYwZzhsQXFFQUprUkpxMjFONzNzaG9UMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6WyJyZWFkOnNjb3JlcyIsInJlYWQ6dXNlcnMiLCJ3cml0ZTpsZWFkZXJib2FyZCIsIndyaXRlOnNjb3JlcyIsIndyaXRlOnVzZXJzIl19.YyQUeX1ttxPF2CUGOlE9m3dBBbi8kDbFXq7-2dld3YPctHJb_wgRxc10RFcyryLkSOdbWFdELoF0sDRh2miEYchdrit7Ac0rTufWkn7pfv4SV8e9yYmlCV-cVBtDjKPDQP2e7TDSuoXOOVBcbdlhyro524bEqAibzWPqfh5apn1HeP_tvbHqdZRdrRZOVu1W89f7uaoua9-DmBASSgeO3KixLYREHAPAI2kFgt2YmWZ-Y_474A2KoIAJgwrbhG094sbDiBuuhRRl2GUURLqbxRB0gIRS1ut4J2DGvkr59t5ev789XIWc4zI3rHvBLJ0hGDyi66Ip8TZW3D-pkNCl6Q",
			username:      "testing",
			permission:    "",
			want:          http.StatusInternalServerError,
			err:           "test",
		},
		{
			name:          "user doesn't match, invalid permissions",
			matchingUser:  matchingUser,
			hasPermission: HasPermission,
			token:         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InpuNmd6ZnBxZDRZbU5hMUZabzFTSiJ9.eyJodHRwOi8vZ2VvYnVmZi5jb20vdXNlcm5hbWUiOiJtcnNjcnViIiwiaXNzIjoiaHR0cHM6Ly9kZXYtZ2VvYnVmZi5hdS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWZjNmM5YWRiMTBkNmQwMDZmNjEwNTk2IiwiYXVkIjpbImh0dHBzOi8vZGV2LWdlb2J1ZmYtYXBpLmNvbSIsImh0dHBzOi8vZGV2LWdlb2J1ZmYuYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTYwODgwNDEwMywiZXhwIjoxNjA4ODkwNTAzLCJhenAiOiJpUXRrTmc2cHYwZzhsQXFFQUprUkpxMjFONzNzaG9UMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6W119.IGUKHVYhGsH3BnpwzYUTVc-hTQjy8FdQT5OeRrR9UIDFpqgVgG1AHJ4yXiaztyva0rXGgA-YsWOJCL9YlpA-7EcBbCT2IomdJT8FbsoyZVRH5XlWJ3MVXaB5_mMdXeHIeEK-TeZZGYKyoWBrClOmvTjHA2Z1-dK4A9ScEUwhYCVQ7usnueiwza-dvNeCzOecnhVRdcvKv4FGBqrjjPeeYlsgL5n7htNVvJKss9wUlN8ucWdJX4VK3-juXOp3PBWsjaEdwBQpWcnHw8MP4lTZ10Xs5AqCt3LktEvarsia4qdeytFPs2jaVpT4Sm_U9nOCae7wKnDa0_nOdWuwsNDyVg",
			username:      "testing",
			permission:    "read:scores",
			want:          http.StatusUnauthorized,
			err:           "missing or invalid permissions",
		},
		{
			name:          "happy path, matching user",
			matchingUser:  matchingUser,
			hasPermission: HasPermission,
			token:         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InpuNmd6ZnBxZDRZbU5hMUZabzFTSiJ9.eyJodHRwOi8vZ2VvYnVmZi5jb20vdXNlcm5hbWUiOiJtcnNjcnViIiwiaXNzIjoiaHR0cHM6Ly9kZXYtZ2VvYnVmZi5hdS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWZjNmM5YWRiMTBkNmQwMDZmNjEwNTk2IiwiYXVkIjpbImh0dHBzOi8vZGV2LWdlb2J1ZmYtYXBpLmNvbSIsImh0dHBzOi8vZGV2LWdlb2J1ZmYuYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTYwODc5Njk5NiwiZXhwIjoxNjA4ODgzMzk2LCJhenAiOiJpUXRrTmc2cHYwZzhsQXFFQUprUkpxMjFONzNzaG9UMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6WyJyZWFkOnNjb3JlcyIsInJlYWQ6dXNlcnMiLCJ3cml0ZTpsZWFkZXJib2FyZCIsIndyaXRlOnNjb3JlcyIsIndyaXRlOnVzZXJzIl19.YyQUeX1ttxPF2CUGOlE9m3dBBbi8kDbFXq7-2dld3YPctHJb_wgRxc10RFcyryLkSOdbWFdELoF0sDRh2miEYchdrit7Ac0rTufWkn7pfv4SV8e9yYmlCV-cVBtDjKPDQP2e7TDSuoXOOVBcbdlhyro524bEqAibzWPqfh5apn1HeP_tvbHqdZRdrRZOVu1W89f7uaoua9-DmBASSgeO3KixLYREHAPAI2kFgt2YmWZ-Y_474A2KoIAJgwrbhG094sbDiBuuhRRl2GUURLqbxRB0gIRS1ut4J2DGvkr59t5ev789XIWc4zI3rHvBLJ0hGDyi66Ip8TZW3D-pkNCl6Q",
			username:      "mrscrub",
			permission:    "",
			want:          200,
			err:           "",
		},
		{
			name:          "happy path, not matching user, valid permissions",
			matchingUser:  matchingUser,
			hasPermission: HasPermission,
			token:         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InpuNmd6ZnBxZDRZbU5hMUZabzFTSiJ9.eyJodHRwOi8vZ2VvYnVmZi5jb20vdXNlcm5hbWUiOiJtcnNjcnViIiwiaXNzIjoiaHR0cHM6Ly9kZXYtZ2VvYnVmZi5hdS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWZjNmM5YWRiMTBkNmQwMDZmNjEwNTk2IiwiYXVkIjpbImh0dHBzOi8vZGV2LWdlb2J1ZmYtYXBpLmNvbSIsImh0dHBzOi8vZGV2LWdlb2J1ZmYuYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTYwODc5Njk5NiwiZXhwIjoxNjA4ODgzMzk2LCJhenAiOiJpUXRrTmc2cHYwZzhsQXFFQUprUkpxMjFONzNzaG9UMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6WyJyZWFkOnNjb3JlcyIsInJlYWQ6dXNlcnMiLCJ3cml0ZTpsZWFkZXJib2FyZCIsIndyaXRlOnNjb3JlcyIsIndyaXRlOnVzZXJzIl19.YyQUeX1ttxPF2CUGOlE9m3dBBbi8kDbFXq7-2dld3YPctHJb_wgRxc10RFcyryLkSOdbWFdELoF0sDRh2miEYchdrit7Ac0rTufWkn7pfv4SV8e9yYmlCV-cVBtDjKPDQP2e7TDSuoXOOVBcbdlhyro524bEqAibzWPqfh5apn1HeP_tvbHqdZRdrRZOVu1W89f7uaoua9-DmBASSgeO3KixLYREHAPAI2kFgt2YmWZ-Y_474A2KoIAJgwrbhG094sbDiBuuhRRl2GUURLqbxRB0gIRS1ut4J2DGvkr59t5ev789XIWc4zI3rHvBLJ0hGDyi66Ip8TZW3D-pkNCl6Q",
			username:      "testing",
			permission:    "read:scores",
			want:          200,
			err:           "",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			matchingUser = tc.matchingUser
			HasPermission = tc.hasPermission

			request, err := http.NewRequest("GET", "", nil)
			if err != nil {
				t.Errorf("error creating request: %v", err)
			}
			request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tc.token))

			uv := UserValidation{
				Request:    request,
				Permission: tc.permission,
				Identifier: "http://geobuff.com/username",
				Key:        tc.username,
			}

			result, err := ValidUser(uv)
			if err != nil {
				if err.Error() != tc.err {
					t.Fatalf("expected error %v; got %v", tc.err, err.Error())
				}
			} else if tc.err != "" {
				t.Fatalf("expected error %v; got nil", tc.err)
			}

			if result != tc.want {
				t.Fatalf("got %v; want %v", result, tc.want)
			}
		})
	}
}
