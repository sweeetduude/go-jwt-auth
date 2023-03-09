package main

import (
	"fmt"
	"net/http"

	jwtauth "github.com/sweeetduude/go-jwt-auth"
)

var secretKey = "YourSecretKey123" // Keep your signing key secret!

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})

	// User jwtauth.Authenticate to auth a subject (e.g. a user id),
	// sign it using your secret key and set expire time in seconds.
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		err := jwtauth.Authenticate("user123", secretKey, 60*60*24*7, w)

		if err != nil {
			fmt.Println("authentication error")
		}
	})

	// Access the validated subject with jwtauth.Validate.
	// Function will return string value "user123" in this example.
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		subject, err := jwtauth.Validate(secretKey, *r)

		if err != nil {
			fmt.Println("user validation error")
		} else {
			fmt.Printf("user %s is logged in", subject)
		}
	})

	// Use function jwtauth.Revoke to remove the auth cookie.
	http.HandleFunc("/signout", func(w http.ResponseWriter, r *http.Request) {
		jwtauth.Revoke(w)
		fmt.Println("user authentication revoked")
	})

	http.ListenAndServe(":8080", nil)
}
