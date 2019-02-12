// package jwt provides an easy way to perform jwt based authentication for http handle func
package jwt

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	bearer = "Bearer"
	delim  = " "
)

// data is the internal organization to marshal http.Request body into
type data struct {
	Name string
	Buff []byte
}

// Requestor provides an interface to request jwt authentication for http handle func's on
// the client side.
type Requestor interface {
	// Request provides a new http Request with token embedded in it.
	Request(method, url string, claims map[string]interface{}, b []byte) (*http.Request, error)
}

// Validator provides an interface to manage jwt authentication for http calls on the server side.
type Validator interface {
	// Validate validates the token embedded in http.Request body and returns the registered
	// function to forward http request to.
	Validate(r *http.Request) error
}

// manager implements interfaces for both server and client sides.
type manager struct {
	// secret is the secret key used for jwt authentication
	secret []byte
}

// NewRequestor provides an instance of Requestor that allows making http request with embedded
// jwt tokens. Use this on the client side.
func NewRequestor(secret string) Requestor {
	m := new(manager)
	m.secret = []byte(secret)
	return m
}

// NewValidator provides an new instance to manager jwt authentication on the server side.
func NewValidator(secret string) Validator {
	m := new(manager)
	m.secret = []byte(secret)
	return m
}

// Request provides a new token to be used primarily by the HTTP clients.
func (m *manager) Request(method, url string, claims map[string]interface{}, b []byte) (*http.Request, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims(claims)

	tokenString, err := token.SignedString(m.secret)
	if err != nil {
		return nil, fmt.Errorf("%s:%v", "error creating new token", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s:%v", "error creating new http request", err)
	}

	req.Header.Set("X-Custom-Header", "jwt")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", strings.Join([]string{bearer, tokenString}, delim))

	return req, nil
}

// Validate validates the token embedded in http.Request header and returns the registered
// function to forward http request to.
func (m *manager) Validate(r *http.Request) error {
	authParts := strings.Split(r.Header.Get("Authorization"), delim)
	if len(authParts) != 2 || authParts[0] != bearer {
		return fmt.Errorf("invalid authorization in http request header")
	}

	token, err := jwt.Parse(authParts[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method was used in JWT token making it invalid: %v", token.Header["alg"])
		}

		return m.secret, nil
	})
	if err != nil {
		return fmt.Errorf("%s:%v", "invalid JWT token", err)
	}

	if token == nil {
		return fmt.Errorf("%s", "invalid JWT token")
	}

	if !token.Valid {
		return fmt.Errorf("%s", "invalid JWT token")
	}

	return nil
}
