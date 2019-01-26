package jwt

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	secret     = "secret"
	nameHello  = "hello"
	nameCustom = "custom"
	output     = "hello world"
)

func CustomBuffer(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = fmt.Fprintf(w, "%s", string(b))
}

func HelloWorld(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintf(w, "%s", output)
}

func Validate(w http.ResponseWriter, r *http.Request) {
	jwt := NewValidator(secret)

	jwt.Register(nameHello, HelloWorld)
	jwt.Register(nameCustom, CustomBuffer)

	valid, f, err := jwt.Validate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	if f != nil {
		f(w, r)
	}
}

func Rotate(w http.ResponseWriter, r *http.Request) {
	jwt := NewValidator(secret)

	jwt.Register(nameHello, HelloWorld)
	jwt.Register(nameCustom, CustomBuffer)

	if err := jwt.Rotate("newKey"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	valid, f, err := jwt.Validate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	if f != nil {
		f(w, r)
	}
}

func TestManager_Validate(t *testing.T) {
	jwt := NewRequestor(secret)

	r, err := jwt.Request("/", nameHello, nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Validate)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, r)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	if rr.Body.String() != output {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), output)
	}
}

func TestManager_Rotate(t *testing.T) {
	jwt := NewRequestor(secret)

	r, err := jwt.Request("/", nameHello, nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Rotate)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, r)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}

	// Check the response body is what we expect.
	expected := `invalid JWT token:signature is invalid
`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got [%v] want [%v]",
			rr.Body.String(), expected)
	}
}

func TestManager_CustomBuffer(t *testing.T) {
	jwt := NewRequestor(secret)

	r, err := jwt.Request("/", nameCustom, []byte("custom func"))
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Validate)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, r)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	if rr.Body.String() != "custom func" {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), "custom func")
	}
}
