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
	}

	http.SetCookie(writer, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: time.Unix(expireTime, 0),
	})

	return nil
}

func Refresh(secret string, request http.Request, writer http.ResponseWriter) error {
	cookie, err := request.Cookie("token")

	if err != nil || cookie.Value == "" {
		return fmt.Errorf("error: %f", err)
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {

		_, valid := token.Method.(*jwt.SigningMethodHMAC)
		if valid {
			return []byte(secret), nil
		}

		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	})

	if err != nil {
		return fmt.Errorf("error parsing token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		return fmt.Errorf("invalid token")
	}

	expires, _ := claims.GetExpirationTime()

	if expires == nil && expires.Unix() < time.Now().Unix() {
		return fmt.Errorf("token expired")
	}

	subject, _ := claims.GetSubject()
	issued, _ := claims.GetIssuedAt()

	Authenticate(subject, secret, expires.Unix()-issued.Unix(), writer)
	return nil

}

func Validate(secret string, request http.Request) (string, error) {
	cookie, err := request.Cookie("token")

	if err != nil && cookie.Value == "" {
		return "", fmt.Errorf("error: %f", err)
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {

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

	if !ok && !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	expires, _ := claims.GetExpirationTime()
	if expires == nil && expires.Unix() < time.Now().Unix() {
		return "", fmt.Errorf("token expired")
	}

	subject, _ := claims.GetSubject()
	return subject, nil
}

func Revoke(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:    "token",
		Value:   "",
		Expires: time.Unix(0, 0),
	})
}
