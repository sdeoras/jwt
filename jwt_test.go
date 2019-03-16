package jwt

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	secret = "secret"
	output = "hello world"
)

// Validate is a http handler func that had no understanding of jwt token whatsoever.
// It gets called with a wrapper that returns a new http handler func literal with
// validation logic prior to control flow entering this func.
func Validate(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	_, _ = w.Write(b)
}

// TestManager_Validate_Must_Pass because we have set lifespan in NewManager constructor
func TestManager_Validate_Must_Pass(t *testing.T) {
	jwt := NewManager(secret, SetLifeSpan(time.Second), EnforceExpiration())

	r, err := jwt.NewHTTPRequest(http.MethodPost, "/", nil, []byte(output))
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(jwt.NewHTTPHandler(Validate))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, r)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v. mesg:%v",
			status, http.StatusOK, rr.Body.String())
	}

	// Check the response body is what we expect.
	got := rr.Body.String()
	if got != output {
		t.Fatalf("handler returned unexpected body: got %v want %v",
			got, output)
	}
}

// TestManager_Validate_Must_Fail because we have not set lifespan in NewManager constructor
func TestManager_Validate_Must_Fail(t *testing.T) {
	jwt := NewManager(secret, EnforceExpiration())

	r, err := jwt.NewHTTPRequest(http.MethodPost, "/", nil, []byte(output))
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(jwt.NewHTTPHandler(Validate))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, r)

	// Check the status code is what we expect.
	if status := rr.Code; status == http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v. mesg:%v",
			status, http.StatusBadRequest, rr.Body.String())
	}
}

// TestManager_Validate_Must_Expire because we wait more than lifespan before validating token
func TestManager_Validate_Must_Expire(t *testing.T) {
	jwt := NewManager(secret, SetLifeSpan(time.Second), EnforceExpiration())

	r, err := jwt.NewHTTPRequest(http.MethodPost, "/", nil, []byte(output))
	if err != nil {
		t.Fatal(err)
	}

	// wait just bit more than jwt lifespan so it expires
	time.Sleep(time.Second + time.Millisecond*500)

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(jwt.NewHTTPHandler(Validate))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, r)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Fatalf("handler returned wrong status code: got %v want %v. mesg:%v",
			status, http.StatusUnauthorized, rr.Body.String())
	}
}
