package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/nu7hatch/gouuid"
)

const bodyTemplate = `
<html>
  <head>
    <title>{{ .Title }}</title>
  </head>
  <body>
    <p>
	  Hi,<br />
	  <br />
      You are receiving this email because you asked to sign in to your account on {{ .BaseURL }}.
	  If this was an accident, or someone else initiated the email, you can ignore this.
	</p>
	<p>
      To sign in to {{ .BaseURL }} on the web, click <a href="{{ .BaseURL }}/auth/{{ .AuthHash }}?redirect={{ .RedirectURL }}">here</a>
    </p>
</body>
</html>`

type AuthClaims struct {
	User string `json:"user"`
	jwt.StandardClaims
}

var secretKey interface{} = []byte("AuthKey?")

func getSecretKey(token *jwt.Token) (interface{}, error) {
	return secretKey, nil
}

func CreateAuthToken(user string) (string, error) {
	standardClaims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "test",
	}

	claims := AuthClaims{
		user,
		standardClaims,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secretKey)
}

func HasValidAuthToken(v string) bool {
	token, err := jwt.ParseWithClaims(v, &AuthClaims{}, getSecretKey)

	if err != nil {
		fmt.Println(err)
		return false
	}

	if _, ok := token.Claims.(*AuthClaims); ok && token.Valid {
		return true
	} else {
		return false
	}
}

func GenerateHashString() (string, error) {
	hash, err := uuid.NewV4()

	if err != nil {
		return "", err
	}

	return hash.String(), nil
}

func SendAuthEmail(recipient string, authHash, redirectURL string) error {
	pass := os.Getenv("EMAIL_PASS")

	if pass != "" {
		return actuallySendAuthEmail(recipient, authHash, redirectURL)
	}

	return errors.New("Failed to send email")
}

func actuallySendAuthEmail(recipient string, authHash, redirectURL string) error {
	sender := NewSender(os.Getenv("EMAIL_ADDRESS"), os.Getenv("EMAIL_PASS"))

	recipients := []string{
		recipient,
	}

	subject := "magic-link-auth Sign-in"
	buf := &bytes.Buffer{}
	ctx := struct {
		Title       string
		AuthHash    string
		RedirectURL string
		BaseURL     string
	}{
		Title:       "magic-link-auth Sign-in",
		AuthHash:    authHash,
		BaseURL:     "http://0.0.0.0:8000",
		RedirectURL: redirectURL,
	}
	if err := render("body", bodyTemplate, ctx, buf); err != nil {
		return err
	}

	return sender.SendMail(recipients, subject, buf.String())
}
