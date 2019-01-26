// package jwt provides an easy way to perform jwt based authentication for http handle func
package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

// data is the internal organization to marshal http.Request body into
type data struct {
	Token string
	Name  string
	Buff  []byte
}

// Requestor provides an interface to request jwt authentication for http handle func's on
// the client side.
type Requestor interface {
	// Request provides a new http Request with token embedded in it.
	Request(url, funcName string, funcData []byte) (*http.Request, error)
}

// Validator provides an interface to manage jwt authentication for http calls on the server side.
type Validator interface {
	// Validate validates the token embedded in http.Request body and returns the registered
	// function to forward http request to.
	Validate(r *http.Request) (bool, func(w http.ResponseWriter, r *http.Request), error)
	// Rotate will rotate key by first validating token embedded in the http request body.
	Rotate(key string) error
	// Register registers HTTP handle func against a nameHello. The nameHello can be requested in the
	// HTTP call to forward HTTP request to the function associated with that nameHello.
	Register(name string, f func(w http.ResponseWriter, r *http.Request))
}

// manager implements interfaces for both server and client sides.
type manager struct {
	// secret is the secret key used for jwt authentication
	secret []byte
	// registry is the internal bookkeeping for registered http handle funcs.
	registry map[string]func(w http.ResponseWriter, r *http.Request)
	// mu is the lock to manage concurrent writes to manager's state.
	mu sync.Mutex
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
	m.registry = make(map[string]func(w http.ResponseWriter, r *http.Request))
	return m
}

// Request provides a new token to be used primarily by the HTTP clients.
func (m *manager) Request(url, funcName string, funcData []byte) (*http.Request, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = "nameHello"
	tokenString, err := token.SignedString(m.secret)
	if err != nil {
		return nil, fmt.Errorf("%s:%v", "error creating new token", err)
	}

	d := new(data)
	d.Token = tokenString
	d.Name = funcName
	d.Buff = funcData

	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("%s:%v", "error marshaling data during http request creation", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s:%v", "error creating new http request", err)
	}

	req.Header.Set("X-Custom-Header", "jwt")
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

// Validate validates the token embedded in http.Request body and returns the registered
// function to forward http request to.
func (m *manager) Validate(r *http.Request) (bool, func(w http.ResponseWriter, r *http.Request), error) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false, nil, fmt.Errorf("%s:%v", "error reading http request reader", err)
	}
	defer r.Body.Close()

	t := new(data)
	if err := json.Unmarshal(b, t); err != nil {
		return false, nil, fmt.Errorf("%s:%v", "error unmarshing http request to get jwt token", err)
	}

	if len(t.Token) == 0 {
		return false, nil, fmt.Errorf("%s", "jwt token length is zero")
	}

	token, err := jwt.Parse(t.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method was used in JWT token making it invalid: %v", token.Header["alg"])
		}

		return m.secret, nil
	})
	if err != nil {
		return false, nil, fmt.Errorf("%s:%v", "invalid JWT token", err)
	}

	if token == nil {
		return false, nil, fmt.Errorf("%s", "invalid JWT token")
	}

	if !token.Valid {
		return false, nil, fmt.Errorf("%s", "invalid JWT token")
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(t.Buff))

	if f, ok := m.registry[t.Name]; !ok {
		return true, nil, nil
	} else {
		return true, f, nil
	}
}

// Rotate will rotate key by first validating token embedded in the http request body.
func (m *manager) Rotate(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.secret = []byte(key)
	return nil
}

// Register registers HTTP handle func against a nameHello. The nameHello can be requested in the
// HTTP call to forward HTTP request to the function associated with that nameHello.
func (m *manager) Register(name string, f func(w http.ResponseWriter, r *http.Request)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.registry[name] = f
}
