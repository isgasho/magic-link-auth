package main

import (
	"fmt"
	"io"
	"net/http"
	"text/template"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

const authCookieName string = "_krb_cookie"

const emailLoginTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>{{ .Title }} :: Email Login</title>
  </head>
<body>
  <main class="container">
    <article class="grid">
      <div>
        <hgroup>
          <h1>Email Login</h1>
          <h2>Please login by entering your email address</h2>
        </hgroup>
        <form method="GET" action="/magic-link">
		  <input type="hidden" name="redirect" value="{{ .Redirect }}">
          <input type="text" name="email" placeholder="Email address" aria-label="Email" autocomplete="email" required>
          <button type="submit" class="contrast">Login</button>
        </form>
      </div>
    <div></div>
  </article>
</main>
</body>
</html>
`

const unauthenticatedTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>{{ .Title }} :: Unauthenticated</title>
  </head>
<body>
  <main class="container">
    <article class="grid">
      <div>
        <hgroup>
          <h1>Unauthenticated</h1>
          <h2>Authentication required. Please login with one of the options below:</h2>
        </hgroup>
		<form>
		  <button formaction="/login">Email</button>
		</form>
      </div>
    <div></div>
  </article>
</main>
</body>
</html>
`

const successTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>{{ .Title }} :: Success</title>
  </head>
<body>
  <main class="container">
    <article class="grid">
      <div>
        <hgroup>
          <h1>Success!</h1>
          <h2>Magic Link successfully sent via {{ .Type }} to {{ .Dest }}</h2>
        </hgroup>
      </div>
    <div></div>
  </article>
</main>
</body>
</html>
`

const indexTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>{{ .Title }} :: Index</title>
  </head>
<body>
  <main class="container">
    <article class="grid">
	  <p>Hello World</p>
  </article>
</main>
</body>
</html>
`

func render(name, tmpl string, ctx interface{}, w io.Writer) error {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		return err
	}

	return t.Execute(w, ctx)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := struct {
		Title    string
		Redirect string
	}{
		Title:    "magic-link-auth Demo",
		Redirect: r.Referer(),
	}

	if err := render("login", emailLoginTemplate, ctx, w); err != nil {
		fmt.Fprintf(w, "error %w", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	redirect := params.Get("redirect")

	vars := mux.Vars(r)
	hash := vars["hash"]

	email, err := getEmailFromHash(hash)

	if err != nil || email == "" {
		w.WriteHeader(404)
		fmt.Fprintln(w, "Invalid hash")
		return
	}

	token, err := CreateAuthToken(email)

	if err != nil {
		fmt.Fprintln(w, "failed to create auth token")
		return
	}

	c := http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Expires:  time.Now().Add(time.Hour),
		HttpOnly: false,
		MaxAge:   50000,
		Path:     "/",
		Domain:   "0.0.0.0:8000",
	}

	http.SetCookie(w, &c)

	http.Redirect(w, r, redirect, http.StatusFound)
}

func UnauthenticatedHandler(w http.ResponseWriter, r *http.Request) {
	ctx := struct {
		Title string
	}{
		Title: "magic-link-auth Demo",
	}

	if err := render("unauthenticated", unauthenticatedTemplate, ctx, w); err != nil {
		fmt.Fprintf(w, "error %w", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func isValidCookie(c *http.Cookie) bool {
	if c.Name != authCookieName {
		return false
	}

	return HasValidAuthToken(c.Value)
}

func getEmailFromHash(hash string) (string, error) {
	data, err := db.Get([]byte(fmt.Sprintf("/magic/%s/email", hash)))
	if err != nil {
		return "Error", err
	}

	return string(data), nil
}

func IsAuthenticated(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(authCookieName)

		if err == nil && c != nil && isValidCookie(c) {
			f(w, r)
		} else {
			// cookie not present or invalid
			UnauthenticatedHandler(w, r)
		}
	}
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	ctx := struct {
		Title string
	}{
		Title: "magic-link-auth Demo",
	}

	if err := render("index", indexTemplate, ctx, w); err != nil {
		fmt.Fprintf(w, "error %w", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func SaveMagicString(email string, hash string) error {
	if err := db.Put([]byte(fmt.Sprintf("/magic/%s/email", hash)), []byte(email)); err != nil {
		return err
	}

	expires := time.Now().Add(time.Minute * 15)
	data, err := expires.GobEncode()
	if err != nil {
		return err
	}
	if err := db.Put([]byte(fmt.Sprintf("/magic/%s/expires", hash)), data); err != nil {
		return err
	}

	return nil
}

func MagicLinkHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	email := params.Get("email")
	redirect := params.Get("redirect")

	if email == "" {
		fmt.Fprintln(w, "Error: must provide an email query parameter")
		return
	}

	hash, err := GenerateHashString()

	err = SaveMagicString(email, hash)

	if err != nil {
		fmt.Fprintln(w, err)
		return
	}

	err = SendAuthEmail(email, hash, redirect)

	if err != nil {
		fmt.Fprintln(w, err)
		return
	}

	ctx := struct {
		Title string
		Type  string
		Dest  string
	}{
		Title: "magic-link-auth Demo",
		Type:  "email",
		Dest:  email,
	}

	if err := render("success", successTemplate, ctx, w); err != nil {
		fmt.Fprintf(w, "error %w", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
