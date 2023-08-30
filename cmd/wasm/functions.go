package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"syscall/js"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type SimplePost struct {
	Signature string
	PublicKey *rsa.PublicKey
	Message []byte
}

type Config struct {
    Host     string
    Port     string
    Password string
    User     string
    DBName   string
    SSLMode  string
}

type User struct {
    Email     string
    Password  string
    PublicKey string
}

func RegisterFunc(this js.Value, args []js.Value) interface{} {
	email := []byte(args[0].String())
	password := []byte(args[1].String())
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		// reject := args[1]
		go func() {
			publicKey := publicKey()

			db, err := NewConnection()
			if err != nil {
				log.Fatal(err)
			}
			// defer db.DB().Close()

			user := User{
				Email:     string(email),
				Password:  string(password),
				PublicKey: publicKey,
			}
			result := db.Create(&user)
			if result.Error != nil {
				log.Fatal(result.Error)
			}

			resolve.Invoke(js.ValueOf(fmt.Sprintf("HELLO")))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func NewConnection() (*gorm.DB, error) {
    configurations := Config{
        Host:     "localhost",
        Port:     "5432",
        Password: "12345678",
        User:     "postgres",
        DBName:   "networking",
        SSLMode:  "disable",
    }
    dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", configurations.Host, configurations.Port, configurations.User, configurations.Password, configurations.DBName, configurations.SSLMode)
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        return nil, err
    }
    return db, nil
}

func publicKey() string{
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

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