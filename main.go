package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prologic/bitcask"
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

func buildRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/", IsAuthenticated(ProtectedHandler)).Methods("GET")
	router.HandleFunc("/login", LoginHandler).Methods("GET")
	router.HandleFunc("/auth/{hash}", AuthHandler).Methods("GET")
	router.HandleFunc("/magic-link", MagicLinkHandler).Methods("GET")

	return router
}

func main() {
	var err error

	db, err = bitcask.Open("./magic-link-auth.db")
	if err != nil {
		log.Fatalf("error opening database: %w", err)
	}

	router := buildRouter()

	http.Handle("/", &Server{router})

	log.Println("magic-auth-link v0.0.0 listening on http://0.0.0.0:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
