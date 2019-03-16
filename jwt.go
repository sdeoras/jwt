// package jwt provides an easy way to perform jwt based authentication for http handle func
package jwt

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	authorization = "Authorization"
	bearer        = "Bearer"
	delim         = " "
	exp           = "exp"
)

// manager implements interfaces for both server and client sides.
type manager struct {
	// secret is the secret key used for jwt authentication
	secret []byte
	// options are jwt settings such as lifespan, issuer, audience and so on
	options []Option
}

// NewManager provides a new instance of jwt manager
func NewManager(secret string, options ...Option) Manager {
	m := new(manager)
	m.secret = []byte(secret)
	m.options = options
	return m
}

// NewHTTPHandler returns a new http handler that wraps input http handler in a closure
// such that jwt authentication is enabled prior to control being passed to the input handler
func (m *manager) NewHTTPHandler(f func(
	w http.ResponseWriter, r *http.Request),
) func(
	w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := m.Validate(r); err != nil {
			http.Error(w, fmt.Sprintf("error validating request:%v", err), http.StatusUnauthorized)
			return
		}
		// forward to input func
		f(w, r)
	}
}

// NewHTTPRequest provides a new token to be used primarily by the HTTP clients.
func (m *manager) NewHTTPRequest(method, url string, claims map[string]interface{}, b []byte) (*http.Request, error) {
	token, err := m.GetToken(claims)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s:%v", "error creating new http request", err)
	}

	req.Header.Set("X-Custom-Header", "jwt")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", strings.Join([]string{bearer, token}, delim))

	return req, nil
}

func (m *manager) GetToken(claims map[string]interface{}) (string, error) {
	if claims == nil {
		claims = make(map[string]interface{})
	}

	// add claims to jwt token overriding input with options set in constructor
	for i := range m.options {
		opt, ok := m.options[i].(*option)
		if !ok {
			return "", fmt.Errorf("error in type assertion in jwt token")
		}

		switch opt.optionType {
		case optEnforceExpiry: // do nothing, this opt is for the server side
		case optLifeSpan:
			lifespan, ok := m.options[i].GetValue().(time.Duration)
			if !ok {
				return "", fmt.Errorf("error in type assertion in lifespan option")
			}
			claims[exp] = time.Now().Add(lifespan).Unix()
		default:
			return "", fmt.Errorf("invalid option type")
		}
	}

	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims(claims)

	tokenString, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("%s:%v", "error creating new token", err)
	}

	return tokenString, nil
}

func (m *manager) SetToken(token string, req *http.Request) {
	req.Header.Set("X-Custom-Header", "jwt")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", strings.Join([]string{bearer, token}, delim))
}

// Validate validates the token embedded in http.Request header and returns the registered
// function to forward http request to.
// If JWT token is not found in http header, it looks into URL query and tries to get it
// from there.
func (m *manager) Validate(r *http.Request) error {
	tokenString, err := getToken(r)
	if err != nil {
		return err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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

	for i := range m.options {
		opt, ok := m.options[i].(*option)
		if !ok {
			return fmt.Errorf("error in type assertion in jwt token")
		}

		switch opt.optionType {
		case optLifeSpan: // do nothing, this option is for the client side
		case optEnforceExpiry: // if enforce is set, claims must have expiry
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return fmt.Errorf("error in type assertion in jwt claims")
			}

			if _, ok := claims[exp]; !ok {
				return fmt.Errorf("all claims must have expiry in their claims")
			}
		default:
			return fmt.Errorf("invalid option type")
		}
	}

	return nil
}

func getToken(r *http.Request) (string, error) {
	authParts := strings.Split(r.Header.Get(authorization), delim)
	if len(authParts) != 2 || authParts[0] != bearer {
		return "", fmt.Errorf("invalid auth since no JWT auth token found")
	} else {
		return authParts[1], nil
	}
}
