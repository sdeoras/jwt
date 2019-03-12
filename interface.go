package jwt

import "net/http"

// Manager defines the interface for jwt related methods
type Manager interface {
	// server side -----

	// Validate validates the token embedded in http.Request body and returns the registered
	// function to forward http request to.
	Validate(r *http.Request) error
	// NewHTTPHandler wraps input http handler into a closure such that jwt authentication
	// is enabled prior to execution of input handler.
	NewHTTPHandler(f func(
		w http.ResponseWriter, r *http.Request),
	) func(
		w http.ResponseWriter, r *http.Request)

	// client side -----

	// NewHTTPRequest provides a new http Request with token embedded in its header.
	// Authorization: Bearer <token>
	NewHTTPRequest(method, url string,
		claims map[string]interface{}, b []byte) (*http.Request, error)
	// GetToken gets a token string
	GetToken(claims map[string]interface{}) (string, error)
	// SetToken sets token for input http request
	SetToken(token string, req *http.Request)
}
