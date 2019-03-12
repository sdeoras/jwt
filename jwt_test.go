package jwt

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	secret = "secret"
	output = "hello world"
)

func Validate(w http.ResponseWriter, r *http.Request) {
	jwt := NewManager(secret)

	err := jwt.Validate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	_, _ = w.Write(b)
}

func TestManager_Validate(t *testing.T) {
	jwt := NewManager(secret)

	r, err := jwt.NewHTTPRequest(http.MethodPost, "/", nil, []byte(output))
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
	got := rr.Body.String()
	if got != output {
		t.Errorf("handler returned unexpected body: got %v want %v",
			got, output)
	}
}

func TestManager_Validate_via_URL(t *testing.T) {
	jwt := NewManager(secret)
	token, err := jwt.GetToken(nil)
	if err != nil {
		t.Fatal(err)
	}

	r, err := http.NewRequest(http.MethodPost, "/?Authorization="+token, bytes.NewReader([]byte(output)))
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
	got := rr.Body.String()
	if got != output {
		t.Errorf("handler returned unexpected body: got %v want %v",
			got, output)
	}
}
