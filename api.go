package main

import (
	"encoding/json"
	"log"
	"net/http"
	"fmt"
	"strconv"
	"os"

	"github.com/gorilla/mux"
	"github.com/golang-jwt/jwt/v4"
)

type APIServer struct {
	listenAddress string
	store Storage
}

func NewAPIServer(listenAddress string, store Storage) *APIServer {
	return &APIServer{
		listenAddress: listenAddress,
		store: store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/login", makeHTTPHandlerFunc(s.handleLogin))
	router.HandleFunc("/account", makeHTTPHandlerFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHTTPHandlerFunc(s.handleGetAccountByID), s.store))
	router.HandleFunc("/transfer", makeHTTPHandlerFunc(s.handleTransfer))


	log.Println("JSON API server running on port:", s.listenAddress)

	http.ListenAndServe(s.listenAddress, router)
}

// 972947
func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error{
	
	
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed %s", r.Method)
	}

	var req LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	acc, err := s.store.GetAccountByNumber(int(req.Number))
	if err != nil {
		return err //handle this response as json
	}

	if !acc.VaildatePassword(req.Password) {
		return fmt.Errorf("number or password is wrong")
	}
	token, err := createJWT(acc)

	if err != nil {
		return err
	}

	resp := LoginResponse{
		Token: token,
		Number: acc.Number,
	}


	fmt.Printf("%+v\n", acc)

	return WriteJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w, r)
	}

	if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	}
	return fmt.Errorf("method's not alloweed %s", r.Method)
}

func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAccounts()

	if err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		id, err := getID(r)

		if err != nil {
			return err
		}

		account, err := s.store.GetAccountByID(id)

		if err != nil {
			return err
		}

		return WriteJSON(w, http.StatusOK, account)
	}

	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w, r)
	}

	return fmt.Errorf("method not allowed")
	
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	req := new(CreateAccountRequest)
	// createAccountReq := CreateAccountRequest{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}

	account, err := NewAccount(req.FirstName, req.LastName, req.Password)
	if err != nil {
		return err
	}

	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)

	if err != nil {
		return err
	}

	if err :=  s.store.DeleteAccount(id); err!= nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	transferRequest := new(TransferRequest)

	if err := json.NewDecoder(r.Body).Decode(transferRequest); err != nil {
		return err
	}

	defer r.Body.Close()

	return WriteJSON(w, http.StatusOK, transferRequest)
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.WriteHeader(status)
	w.Header().Add("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(v)
}

func createJWT(account *Account) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt" : 15000,
		"accountNumber" : account.Number,
	}

	secret := os.Getenv("JWT_SECRET_GOBANK")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))

}

func permissionDenied(w http.ResponseWriter) {
	WriteJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"})
} 
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjoxNjAwNjcsImV4cGlyZXNBdCI6MTUwMDB9.rt5Q5M_onwn9dNpYOqBc8jHhqO2HOeai_22iOvFTWOU

func withJWTAuth(handlerFunc http.HandlerFunc, s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("x-jwt-token")
		token, err := validateJWT(tokenString)

		if err != nil {
			permissionDenied(w)
			return 
		}

		if !token.Valid {
			permissionDenied(w)
			return
		}

		userID,err := getID(r)

		if err != nil {
			permissionDenied(w)
			return
		}

		account, err := s.GetAccountByID(userID)
		if err != nil {
			permissionDenied(w)
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		if account.Number != int64(claims["accountNumber"].(float64)) {
			permissionDenied(w)
			return
		}

		if err != nil {
			WriteJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"})
			return 
		}

		handlerFunc(w, r)
	}
} 

func validateJWT(tokenString string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET_GOBANK")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string `json:"error"`
}

func makeHTTPHandlerFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err!=nil {
			WriteJSON(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func getID (r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)

	if err != nil {
		return id, fmt.Errorf("invalid id given %s", idStr)
	}
	
	return id, nil
}