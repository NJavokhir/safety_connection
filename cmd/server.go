package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	// "io"
	"io/ioutil"
	"net/http"

	"github.com/rs/cors"
)

type SimplePost struct {
	Signature     string `json:"signature"`
	PublicKey *rsa.PublicKey `json:"publicKey"`
	Message []byte `json:"message"`
}

func main() {
	http.HandleFunc("/post-signature", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		r_bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err.Error())
		}

		var mysimplePost SimplePost
		if json.Unmarshal(r_bs, &mysimplePost); err != nil {
			fmt.Println(err.Error())
		}

		fmt.Println("MY_SIMPLE_POST", mysimplePost.Signature)
		fmt.Println("PublicKey", mysimplePost.PublicKey)
		fmt.Println("Message", mysimplePost.Message)

		hash := sha256.Sum256([]byte(mysimplePost.Message))
		signature, err := base64.StdEncoding.DecodeString(mysimplePost.Signature)
		if err != nil {
			fmt.Errorf("failed to decode base64 signature: %v", err)
		}
		err = rsa.VerifyPKCS1v15(mysimplePost.PublicKey, crypto.SHA256, hash[:], signature)
		if err != nil {
			fmt.Errorf("signature verification failed: %v", err)
		} else if (err == nil) {
			str := string(mysimplePost.Message)
	
			fmt.Println("Original Message: ", str)
	
			response := str
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, response)
		}
	})

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8080"},         // Allow the frontend server to access the backend server
		AllowedMethods:   []string{"GET", "POST", "PUT", "OPTIONS"}, // Allow these HTTP methods
		AllowedHeaders:   []string{"Accept", "content-type"},        // Allow these HTTP headers
		AllowCredentials: true,                                      // Allow cookies
	})
	handler := c.Handler(http.DefaultServeMux)
	http.ListenAndServe(":9090", handler)
}