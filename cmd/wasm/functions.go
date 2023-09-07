package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"syscall/js"
	"golang.org/x/crypto/bcrypt"
)

type SimplePost struct {
	Signature string
	PublicKey *rsa.PublicKey
	Message []byte
}

type User struct {
    Email     string
    Password  string
    PublicKey *rsa.PublicKey
	Signature string
}

func RegisterFunc(this js.Value, args []js.Value) interface{} {
	email := []byte(args[0].String())
	password := []byte(args[1].String())
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			// Generate private key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatal(err)
			}
			// publicKey := publicKey(privateKey)

			hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			data := append(email, string(hashedPass)...)
			hashed := sha256.Sum256([]byte(data))
			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
			if err != nil {
				panic(err)
			}
			signatureBase64 := base64.StdEncoding.EncodeToString(signature)


			var url = "http://localhost:9090/register"
			user := User{
				Email:     string(email),
				Password:  string(hashedPass),
				PublicKey: &privateKey.PublicKey,
				Signature:  signatureBase64,
			}
			user_bs, err := json.Marshal(user)
			if err != nil {
				fmt.Errorf("Error on Marshalling to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on POST"))
			}

			resp, err := http.Post(url, "Content-Type:application/json", bytes.NewReader(user_bs))
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on POST"))
			}

			response_BS, err := io.ReadAll(resp.Body)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error reading response body: ", err.Error())))
			}

			resolve.Invoke(js.ValueOf(fmt.Sprintf(string(response_BS))))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func LoginFunc(this js.Value, args []js.Value) interface{} {
	email := []byte(args[0].String())
	password := []byte(args[1].String())
	resolve_reject_internals := func (this js.Value, args []js.Value) interface{}  {
		resolve := args[0]
		reject := args[1]
		go func ()  {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatal(err)
			}

			data := append(email, password...)
			hashed := sha256.Sum256([]byte(data))
			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
			if err != nil {
				panic(err)
			}
			signatureBase64 := base64.StdEncoding.EncodeToString(signature)

			var url = "http://localhost:9090/login"
			user := User{
				Email: string(email),
				Password: string(password),
				PublicKey: &privateKey.PublicKey,
				Signature: signatureBase64,
			}

			user_bs, err := json.Marshal(user)
			if err != nil {
				fmt.Errorf("Error on Marshalling to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on POST"))
			}

			resp, err := http.Post(url, "Content-Type:application/json", bytes.NewReader(user_bs))
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on POST"))
			}

			response_BS, err := io.ReadAll(resp.Body)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error reading response body: ", err.Error())))
			}

			var originalData map[string]interface{}
			err = json.Unmarshal(response_BS, &originalData)
			

			resolve.Invoke(js.ValueOf(originalData))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func publicKey(privateKey *rsa.PrivateKey) string{
	privKeyBytes := privateKey.D.Bytes()
	privKeyHex := hex.EncodeToString(privKeyBytes)
	js.Global().Get("localStorage").Call("setItem", "privKey", privKeyHex)

	// Convert public key to string
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	publicKeyString := string(publicKeyPEM)

	return publicKeyString
}

func SignString(this js.Value, args []js.Value) interface{} {
	arg0BS := []byte(args[0].String())
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func(input []byte) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				fmt.Errorf("Error on POST to: %s", err.Error())
				reject.Invoke(js.ValueOf("Failure on Post"))
			}

			hash := sha256.Sum256([]byte(input))
			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error hashing: \"%s\"", err.Error())))
			}

			signatureBase64 := base64.StdEncoding.EncodeToString(signature)
			var url = "http://localhost:9090/post-signature"
			simplePost := SimplePost{
				Signature:  signatureBase64,
				PublicKey: &privateKey.PublicKey,
				Message: input,
			}

			simplePost_bs, err := json.Marshal(simplePost)
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on Post"))
			}

			resp, err := http.Post(url, "Content-Type:application/json", bytes.NewReader(simplePost_bs))
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on Post"))
			}

			response_BS, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error reading response body: ", err.Error())))
			}

			resolve.Invoke(js.ValueOf(fmt.Sprintf(string(response_BS))))
		}(arg0BS)
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}