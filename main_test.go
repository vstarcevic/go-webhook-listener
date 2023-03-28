package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var callTests = []struct {
	status int
	key    string
	body   string
}{
	//-- Valid response
	{200, "123456", `{"pusher": { "name": "test", "email": "test@test.com"}}`},
	//-- Valid Response, empty json
	{200, "123456", `{  }`},
	//-- EmptyBody
	{500, "123456", ``},
	//-- Invalid JSON
	{500, "123456", `{`},
	//-- Empty Key
	{500, "", `{"pusher": { "name": "test", "email": "test@test.com"}}`},
}

func TestHTTPAuth(t *testing.T) {

	for _, tt := range callTests {

		userJSON := strings.NewReader(tt.body)
		requestURL := "http://example.com/api/"

		hash := hmac.New(sha256.New, []byte(tt.key))
		if _, err := hash.Write([]byte(tt.body)); err != nil {
			t.Fatal(err)
		}

		request, err := http.NewRequest("POST", requestURL, userJSON)
		request.Header.Add("X-Hub-Signature-256", "sha256="+hex.EncodeToString(hash.Sum(nil)))
		if err != nil {
			t.Fatal(err)
		}

		res := httptest.NewRecorder()
		webhookCatcher(res, request)

		if res.Code != tt.status {
			t.Errorf("Expected %d got: %d\n", tt.status, res.Code)
		}
	}
}
