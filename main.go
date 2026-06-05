package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"
)

type Todo struct {
	ID        int    `json:"id"`
	Text      string `json:"text"`
	Done      bool   `json:"done"`
	CreatedBy string `json:"created_by"`
}

var (
	todos  = []Todo{}
	nextID = 1
	mu     sync.Mutex
)

// insecure HTTP client — needed because ThunderID uses self-signed certificate
var insecureClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	// Use your Mac's IP (192.168.5.2) instead of localhost
	// because inside the cluster, localhost means the container itself
	resp, err := insecureClient.Get("https://192.168.5.2:8090/oauth2/jwks")
	if err != nil {
		return nil, fmt.Errorf("could not fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}
	json.NewDecoder(resp.Body).Decode(&jwks)

	if len(jwks.Keys) == 0 || len(jwks.Keys[0].X5c) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS")
	}

	certBytes := []byte("-----BEGIN CERTIFICATE-----\n" + jwks.Keys[0].X5c[0] + "\n-----END CERTIFICATE-----")
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse cert: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return cert.PublicKey, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	return token.Claims.(jwt.MapClaims), nil
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validateToken(tokenString)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		email := ""
		if e, ok := claims["email"].(string); ok {
			email = e
		} else if sub, ok := claims["sub"].(string); ok {
			email = sub
		}
		r.Header.Set("X-User-Email", email)
		next(w, r)
	}
}

func getTodos(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if todos == nil {
        todos = []Todo{}
    }
	json.NewEncoder(w).Encode(todos)
}

func createTodo(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Text == "" {
		http.Error(w, `{"error":"text is required"}`, http.StatusBadRequest)
		return
	}

	mu.Lock()
	todo := Todo{
		ID:        nextID,
		Text:      body.Text,
		Done:      false,
		CreatedBy: r.Header.Get("X-User-Email"),
	}
	todos = append(todos, todo)
	nextID++
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(todo)
}

func deleteTodo(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/todos/")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	mu.Lock()
	defer mu.Unlock()
	for i, t := range todos {
		if t.ID == id {
			todos = append(todos[:i], todos[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthCheck)

	mux.HandleFunc("/todos", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			authMiddleware(getTodos)(w, r)
		case http.MethodPost:
			authMiddleware(createTodo)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/todos/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			authMiddleware(deleteTodo)(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	handler := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:5173",
			"http://192.168.5.2",
			"http://endpoint-1-frontend-development-default-ec673672.openchoreoapis.localhost:19080",
		},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(mux)

	log.Println("✓ Backend running on http://localhost:8081")
	log.Println("✓ Endpoints: GET/POST /todos, DELETE /todos/:id, GET /health")
	log.Fatal(http.ListenAndServe(":8081", handler))
}