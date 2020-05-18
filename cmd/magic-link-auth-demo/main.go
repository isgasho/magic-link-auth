package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prologic/bitcask"

	magiclinkauth "github.com/prologic/magic-link-auth"
)

type Server struct {
	router *mux.Router
}

var (
	db *bitcask.Bitcask
)

func (server *Server) ServeHTTP(resWriter http.ResponseWriter, req *http.Request) {
	origin := req.Header.Get("Origin")

	if origin != "" {
		resWriter.Header().Set("Access-Control-Allow-Origin",
			origin)
		resWriter.Header().Set("Access-Control-Allow-Methods",
			"POST, GET, OPTIONS, PUT, DELETE")
		resWriter.Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	}

	if req.Method == "OPTIONS" {
		return
	}

	server.router.ServeHTTP(resWriter, req)
}

func buildRouter(m *magiclinkauth.MagicLinkAuth) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/", m.IsAuthenticated(m.ProtectedHandler)).Methods("GET")
	router.HandleFunc("/login", m.LoginHandler).Methods("GET")
	router.HandleFunc("/auth/{hash}", m.AuthHandler).Methods("GET")
	router.HandleFunc("/magic-link", m.MagicLinkHandler).Methods("GET")

	return router
}

func main() {
	var err error

	db, err = bitcask.Open("./magic-link-auth.db")
	if err != nil {
		log.Fatal(fmt.Errorf("error opening database: %w", err))
	}

	m, err := magiclinkauth.NewMagicLinkAuth(db)
	if err != nil {
		log.Fatal(fmt.Errorf("error creating new MagicLinkAuth: %w", err))
	}

	router := buildRouter(m)

	http.Handle("/", &Server{router})

	log.Println("magic-auth-link-demo v0.0.0 listening on http://0.0.0.0:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
