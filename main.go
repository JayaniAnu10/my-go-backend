package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
)

// ─── Database ─────────────────────────────────────────────────────────────────

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "/app/data/todos.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS todos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			text TEXT NOT NULL,
			done BOOLEAN DEFAULT FALSE,
			created_by TEXT
		)
	`)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}
	log.Println("✓ Database initialized at /app/data/todos.db")
}

// ─── Types ────────────────────────────────────────────────────────────────────

type Todo struct {
	ID        int    `json:"id"`
	Text      string `json:"text"`
	Done      bool   `json:"done"`
	CreatedBy string `json:"created_by"`
}

// ─── JWT ──────────────────────────────────────────────────────────────────────

var insecureClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

var (
	cachedPublicKey interface{}
	cachedKeyMu     sync.Mutex
	cachedKeyTime   time.Time
	cacheTTL        = 5 * time.Minute
)

func getPublicKey() (interface{}, error) {
	cachedKeyMu.Lock()
	defer cachedKeyMu.Unlock()

	if cachedPublicKey != nil && time.Since(cachedKeyTime) < cacheTTL {
		return cachedPublicKey, nil
	}

	log.Println("Fetching JWKS from ThunderID...")
	resp, err := insecureClient.Get("http://thunder-service.thunder.svc.cluster.local:8090/oauth2/jwks")
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

	cachedPublicKey = cert.PublicKey
	cachedKeyTime = time.Now()
	log.Println("✓ JWKS fetched and cached successfully")
	return cachedPublicKey, nil
}

func invalidateCache() {
	cachedKeyMu.Lock()
	cachedPublicKey = nil
	cachedKeyMu.Unlock()
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	publicKey, err := getPublicKey()
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil || !token.Valid {
		// Force cache invalidation and retry once in case ThunderID restarted
		log.Println("Token validation failed, invalidating JWKS cache and retrying...")
		invalidateCache()

		publicKey, err = getPublicKey()
		if err != nil {
			return nil, err
		}

		token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		}, jwt.WithoutClaimsValidation())

		if err != nil || !token.Valid {
			return nil, fmt.Errorf("invalid token: %v", err)
		}
	}

	return token.Claims.(jwt.MapClaims), nil
}

// ─── Role resolver ────────────────────────────────────────────────────────────

func resolveRole(claims jwt.MapClaims) string {
	candidateKeys := []string{
		"roles", "role", "groups", "permissions",
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
	}

	normalizeRole := func(value string) string {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "admin") || strings.Contains(lower, "owner") {
			return "admin"
		}
		if strings.Contains(lower, "user") || strings.Contains(lower, "member") {
			return "user"
		}
		return ""
	}

	for _, key := range candidateKeys {
		val := claims[key]
		if arr, ok := val.([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					if role := normalizeRole(s); role != "" {
						return role
					}
				}
			}
		}
		if s, ok := val.(string); ok {
			if role := normalizeRole(s); role != "" {
				return role
			}
		}
	}
	return "user"
}

// ─── Middleware ───────────────────────────────────────────────────────────────

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
			log.Println("Token validation failed:", err)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// Extract email
		email := ""
		if e, ok := claims["email"].(string); ok {
			email = e
		} else if sub, ok := claims["sub"].(string); ok {
			email = sub
		}

		// Extract role
		role := resolveRole(claims)

		r.Header.Set("X-User-Email", email)
		r.Header.Set("X-User-Role", role)

		log.Printf("Request: %s %s | user: %s | role: %s", r.Method, r.URL.Path, email, role)
		next(w, r)
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func getTodos(w http.ResponseWriter, r *http.Request) {
	email := r.Header.Get("X-User-Email")
	role := r.Header.Get("X-User-Role")

	var rows *sql.Rows
	var err error

	if role == "admin" {
		rows, err = db.Query("SELECT id, text, done, created_by FROM todos ORDER BY id DESC")
	} else {
		rows, err = db.Query("SELECT id, text, done, created_by FROM todos WHERE created_by = ? ORDER BY id DESC", email)
	}

	if err != nil {
		log.Println("DB error:", err)
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	todos := []Todo{}
	for rows.Next() {
		var t Todo
		rows.Scan(&t.ID, &t.Text, &t.Done, &t.CreatedBy)
		todos = append(todos, t)
	}

	w.Header().Set("Content-Type", "application/json")
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

	email := r.Header.Get("X-User-Email")
	result, err := db.Exec("INSERT INTO todos (text, done, created_by) VALUES (?, false, ?)", body.Text, email)
	if err != nil {
		log.Println("DB error:", err)
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	todo := Todo{ID: int(id), Text: body.Text, Done: false, CreatedBy: email}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(todo)
}

func deleteTodo(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/todos/")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	email := r.Header.Get("X-User-Email")
	role := r.Header.Get("X-User-Role")

	var result sql.Result
	var err error

	if role == "admin" {
		result, err = db.Exec("DELETE FROM todos WHERE id = ?", id)
	} else {
		result, err = db.Exec("DELETE FROM todos WHERE id = ? AND created_by = ?", id, email)
	}

	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		http.Error(w, `{"error":"not found or not authorized"}`, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	initDB()

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
			"http://192.168.5.1",
			"http://endpoint-1-frontend-development-default-ec673672.openchoreoapis.localhost:19080",
		},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(mux)

	log.Println("✓ Backend running on http://localhost:8081")
	log.Println("✓ Database: /app/data/todos.db")
	log.Println("✓ Endpoints: GET/POST /todos, DELETE /todos/:id, GET /health")
	log.Fatal(http.ListenAndServe(":8081", handler))
}
