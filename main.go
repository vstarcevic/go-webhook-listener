package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

const authKey string = "123456"
const port string = "9000"
const scriptWithPath string = "/home/vlada/deploy-front.sh"

type webhookJSONRespStruct struct {
	Ref    string `json:"ref"`
	Pusher struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"pusher"`
	UpdatedAt string `json:"updated_at"`
}

func main() {

	log.Println("Webhook Listner started")
	log.Println("Listening on Port:", port)

	//-- Run WebhookCatcher when the url :9000/api is called
	http.HandleFunc("/hook", webhookCatcher)
	//-- Run HTTP server on port 9000
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func webhookCatcher(w http.ResponseWriter, r *http.Request) {
	//-- Log Request
	log.Println("Incomming Request")

	boolKeyIsValid := checkAuthKey(r, authKey)

	if !boolKeyIsValid {
		throwError("Hash do not match", w)
		return
	}

	boolJSONProcess := processJSON(r, w)

	// If JSON is not decoded correctly then throw error
	if !boolJSONProcess {
		throwError("Unable to Process JSON Response", w)
		return
	}

	// Execute bash script on hook
	result, err := executeScript()
	if err != nil {
		throwError("Error executing script.", w)
	}
	log.Println(result)

	// Return 200
	w.Write([]byte("Success"))

}

func checkAuthKey(r *http.Request, key string) bool {
	gotHash := strings.SplitN(r.Header.Get("X-Hub-Signature-256"), "=", 2)
	if gotHash[0] != "sha256" {
		return false
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Cannot read the request body: %s\n", err)
		return false
	}

	hash := hmac.New(sha256.New, []byte(key))
	if _, err := hash.Write(b); err != nil {
		log.Printf("Cannot compute the HMAC for request: %s\n", err)
		return false
	}

	expectedHash := hex.EncodeToString(hash.Sum(nil))
	r.Body = io.NopCloser(bytes.NewBuffer(b))

	return gotHash[1] == expectedHash
}

func processJSON(r *http.Request, w http.ResponseWriter) bool {
	log.Println("Processing JSON")

	defer r.Body.Close()

	var t webhookJSONRespStruct

	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		log.Println("Error: ", err)
		return false
	}

	log.Println("Updated At: ", t.UpdatedAt)
	return true
}

func throwError(s string, w http.ResponseWriter) {
	http.Error(w, s, 500)
}

func executeScript() (string, error) {
	cmd, err := exec.Command("/bin/sh", scriptWithPath).Output()
	if err != nil {
		fmt.Printf("error %s", err)
		return "", err
	}
	output := string(cmd)
	return output, nil
}
