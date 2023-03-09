package jwtauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Authenticate(subject string, secret string, expire int64, writer http.ResponseWriter) error {

	expireTime := time.Now().Unix() + expire

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": expireTime,
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		return fmt.Errorf("error when creating JWT: %v", err)
	} else {
		http.SetCookie(writer, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: time.Unix(expireTime, 0),
		})
	}

	return nil
}

func Refresh() {

}

func Validate(secret string, request http.Request) (string, error) {
	tokenString, err := request.Cookie("token")

	if err == nil && tokenString.Value != "" {
		token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {

			_, valid := token.Method.(*jwt.SigningMethodHMAC)
			if valid {
				return []byte(secret), nil
			}

			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		})

		if err != nil {
			return "", fmt.Errorf("error parsing token")
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if ok && token.Valid {
			expires, _ := claims.GetExpirationTime()
			if expires != nil && expires.Unix() > time.Now().Unix() {
				subject, _ := claims.GetSubject()
				return subject, nil
			}

		} else {
			return "", fmt.Errorf("invalid token")
		}

	} else {
		return "", fmt.Errorf("error: %f", err)
	}

	return "", nil
}

func Revoke(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:    "token",
		Value:   "",
		Expires: time.Unix(0, 0),
	})
}
