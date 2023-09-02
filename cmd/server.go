package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"io/ioutil"
	"net/http"

	"github.com/rs/cors"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type SimplePost struct {
	Signature     string `json:"signature"`
	PublicKey *rsa.PublicKey `json:"publicKey"`
	Message []byte `json:"message"`
}

type Config struct {
    Host     string
    Port     string
    Password string
    User     string
    DBName   string
    SSLMode  string
}

type UserReceiving struct {
    Email     string `json:"email"`
    Password  string `json:"password"`
    PublicKey *rsa.PublicKey `json:"publickey"`
	Signature     string `json:"signature"`
}
type UserSending struct {
    EmailS     string `json:"email"`
    PasswordS  string `json:"password"`
    PublicKeyS string `json:"publickey"`
}
type User struct {
	Email    string `gorm:"uniqueIndex;not null"`
	password string `gorm:"not null"`
}

type RequestLogin struct {
	Email    string
	Password string
}

type ResponseLogin struct {
	User *User
}

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/post-signature", postSignatureHandler)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type"},
		AllowCredentials: true,
	})

	handler := c.Handler(http.DefaultServeMux)
	http.ListenAndServe(":9090", handler)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	user, err := parseRequest(r)
	if err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}

	err = verifySignature(user)
	if err != nil {
		httpError(w, err, http.StatusBadRequest)
	}

	err = registerUser(user)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Registration successful")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Came")
	user, err := parseRequest(r)
	if err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}

	err  = verifySignature(user)
	if err != nil {
		httpError(w, err, http.StatusBadRequest)
	}

	_, err = loginUser(user)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Authorize")
}

func parseRequest(r *http.Request) (UserReceiving, error) {
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return UserReceiving{}, err
	}

	var user UserReceiving
	err = json.Unmarshal(body, &user)
	if err != nil {
		return UserReceiving{}, err
	}

	return user, nil
}

func verifySignature(user UserReceiving) error {
	signature, err := base64.StdEncoding.DecodeString(user.Signature)
	if err != nil {
		return nil
	}

	data := user.Email + user.Password
	hashed := sha256.Sum256([]byte(data))

	err = rsa.VerifyPKCS1v15(user.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return err
	}

	return nil
}

func registerUser(user UserReceiving) error {
	publicKeyString, err := PublicKeyToString(user.PublicKey)
	if err != nil {
		return err
	}

	userSending := UserSending{
		EmailS: user.Email,
		PasswordS: user.Password,
		PublicKeyS: publicKeyString,
	}

	db, err := NewConnection()
	if err != nil {
		return err
	}
	defer CloseConnection(db)

	db.AutoMigrate(&userSending)

	result := db.Create(&userSending)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

func loginUser(user UserReceiving) (*ResponseLogin, error) {
	var userDB User

	db, err := NewConnection()
	if err != nil {
		return nil, err
	}
	defer CloseConnection(db)

	err = db.Where("email = ?", user.Email).First(&userDB).Error
	// if err != nil {
	// 	if err == gorm.ErrRecordNotFund {
	// 		return nil, err
	// 	} else {
	// 		return nil, err
	// 	}
	// }

	if user.Password != userDB.password {
		return nil, err
	}

	return &ResponseLogin{User: &userDB}, nil
}

func httpError(w http.ResponseWriter, err error, code int) {
	http.Error(w, err.Error(), code)
}

func NewConnection() (*gorm.DB, error) {
    configurations := Config{
        Host:     "localhost",
        Port:     "5432",
        Password: "Javohirjavohir1?",
        User:     "postgres",
        DBName:   "users",
        SSLMode:  "disable",
    }
    dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", configurations.Host, configurations.Port, configurations.User, configurations.Password, configurations.DBName, configurations.SSLMode)
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: dsn,
	}), &gorm.Config{})
	if err != nil {
		panic("Failed to create a connection to database")
	}

    return db, nil
}

func CloseConnection(db *gorm.DB) {
	dbSQL, err := db.DB()
	if err != nil {
		panic("Failed to close connection from Database")
	}
	dbSQL.Close()
}

func PublicKeyToString(publicKey *rsa.PublicKey) (string, error) {
	// Marshal the public key to DER format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	// Create a PEM block with the marshaled public key
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Encode the PEM block to a string
	publicKeyString := string(pem.EncodeToMemory(pemBlock))

	return publicKeyString, nil
}



func postSignatureHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var post SimplePost
	if err = json.Unmarshal(body, &post); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Post Signature Handler - Signature:", post.Signature)
	fmt.Println("Post Signature Handler - PublicKey:", post.PublicKey)
	fmt.Println("Post Signature Handler - Message:", post.Message)

	// Verify signature logic here

	response := "Signature verified"
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, response)
}

// func verifySignature(message string, signature string, publicKey string) error {
// 	hash := sha256.Sum256([]byte(message))
// 	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
// 	if err != nil {
// 		return fmt.Errorf("failed to decode base64 signature: %v", err)
// 	}

// 	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
// 	if err != nil {
// 		return fmt.Errorf("failed to decode base64 public key: %v", err)
// 	}

// 	parsedPublicKey, err := rsa.PublicKeyFromJSON(publicKeyBytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse public key: %v", err)
// 	}

// 	err = rsa.VerifyPKCS1v15(parsedPublicKey, crypto.SHA256, hash[:], signatureBytes)
// 	if err != nil {
// 		return fmt.Errorf("signature verification failed: %v", err)
// 	}

// 	return nil
// }