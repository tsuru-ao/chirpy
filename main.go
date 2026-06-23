package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/tsuru-ao/chirpy/internal/auth"
	"github.com/tsuru-ao/chirpy/internal/database"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type errResponse struct {
	Error string `json:"error"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const hourExp = 60 * 60

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		panic(err)
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)
	mux := http.NewServeMux()

	apiCfg := &apiConfig{
		dbQueries: dbQueries,
		platform:  os.Getenv("PLATFORM"),
		jwtSecret: os.Getenv("JWT_SECRET"),
		polkaKey:  os.Getenv("POLKA_KEY"),
	}

	fileHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileHandler))
	mux.HandleFunc("GET /api/healthz", handleHealth)
	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)
	mux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)
	mux.HandleFunc("PUT /api/users", apiCfg.handleUpdateUser)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handleGetChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handleDeleteChirp)
	mux.HandleFunc("POST /api/chirps", apiCfg.handleCreateChirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handleWebhooks)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)

	// 3. Configure the HTTP server explicitly using the custom mux
	server := &http.Server{
		Addr:         ":8060",
		Handler:      mux,              // Injects the isolated router
		ReadTimeout:  10 * time.Second, // Prevents resource leaks
		WriteTimeout: 10 * time.Second,
	}

	// 4. Start listening for incoming network requests
	fmt.Println("Server running on http://localhost:8060")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}

func handleHealth(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(200)
	_, _ = rw.Write([]byte("OK"))
}

func (cfg *apiConfig) handleRefresh(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		renderError(err, 401, rw)
		return
	}
	userID, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		renderError(err, 401, rw)
		return
	}
	rw.WriteHeader(200)

	jwt, err := auth.MakeJWT(userID, cfg.jwtSecret, time.Duration(hourExp)*time.Second)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	data, err := json.Marshal(tokenResponse{Token: jwt})
	_, _ = rw.Write(data)
}

func (cfg *apiConfig) handleRevoke(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		renderError(err, 401, rw)
		return
	}
	rw.WriteHeader(204)

	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		renderError(err, 400, rw)
	}
}

func (cfg *apiConfig) handleLogin(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var params parameters
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		renderError(fmt.Errorf("Incorrect email or password"), 401, rw)
		return
	}
	ok, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	if !ok {
		renderError(fmt.Errorf("Incorrect email or password"), 401, rw)
		return
	}
	rw.WriteHeader(200)
	jwt, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Duration(hourExp)*time.Second)
	if err != nil {
		renderError(err, 400, rw)
		return
	}

	refreshToken, err := cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{UserID: user.ID, Token: auth.MakeRefreshToken(), ExpiresAt: time.Now().Add(60 * 24 * time.Hour)})
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	data, err := json.Marshal(User{ID: user.ID, Email: user.Email, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Token: jwt, RefreshToken: refreshToken.Token, IsChirpyRed: user.IsChirpyRed.Bool})
	_, _ = rw.Write(data)
}

func (cfg *apiConfig) handleCreateUser(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var params parameters
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: hashedPassword})
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	rw.WriteHeader(201)
	data, err := json.Marshal(User{ID: user.ID, Email: user.Email, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, IsChirpyRed: user.IsChirpyRed.Bool})
	_, _ = rw.Write(data)
}

func (cfg *apiConfig) handleUpdateUser(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	UserID, err := cfg.validateJWT(r.Header)
	if err != nil {
		renderError(err, 401, rw)
		return
	}
	user, err := cfg.dbQueries.GetUser(r.Context(), UserID)
	if err != nil {
		renderError(err, 404, rw)
		return
	}
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var params parameters
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	updatedAt := time.Now()
	err = cfg.dbQueries.UpdateUser(
		r.Context(),
		database.UpdateUserParams{ID: UserID, Email: params.Email, HashedPassword: hashedPassword, UpdatedAt: updatedAt},
	)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	rw.WriteHeader(200)
	data, err := json.Marshal(User{ID: UserID, Email: params.Email, CreatedAt: user.CreatedAt, UpdatedAt: updatedAt, IsChirpyRed: user.IsChirpyRed.Bool})
	_, _ = rw.Write(data)
}

func (cfg *apiConfig) handleGetChirps(rw http.ResponseWriter, r *http.Request) {
	author_id := r.URL.Query().Get("author_id")
	sorting := r.URL.Query().Get("sort")
	chirps, err := cfg.getChirps(r.Context(), author_id)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	fmt.Println(sorting)
	if sorting != "" {
		asc := sorting == "asc"
		sort.Slice(chirps, func(i, j int) bool {
			if asc {
				return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
			}
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	}
	rw.WriteHeader(200)
	chirpsData := make([]Chirp, 0, len(chirps))
	for _, chirp := range chirps {
		chirpsData = append(chirpsData, Chirp{ID: chirp.ID, Body: CleanChirp(chirp.Body), UserID: chirp.UserID, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt})
	}
	data, err := json.Marshal(chirpsData)
	_, _ = rw.Write(data)
}

func (cfg *apiConfig) handleGetChirp(rw http.ResponseWriter, r *http.Request) {
	chirpUUID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpUUID)

	if err != nil {
		renderError(err, 404, rw)
		return
	}
	rw.WriteHeader(200)

	data, err := json.Marshal(Chirp{ID: chirp.ID, Body: CleanChirp(chirp.Body), UserID: chirp.UserID, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt})
	_, _ = rw.Write(data)
}

func (cfg *apiConfig) handleDeleteChirp(rw http.ResponseWriter, r *http.Request) {
	UserID, err := cfg.validateJWT(r.Header)
	if err != nil {
		renderError(err, 401, rw)
		return
	}
	chirpUUID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpUUID)
	if err != nil {
		renderError(err, 404, rw)
		return
	}
	if chirp.UserID != UserID {
		renderError(fmt.Errorf("not an owner"), 403, rw)
		return
	}
	err = cfg.dbQueries.DeleteChirp(r.Context(), chirpUUID)
	if err != nil {
		renderError(err, 400, rw)
		return
	}

	rw.WriteHeader(204)
}

func (cfg *apiConfig) handleCreateChirp(rw http.ResponseWriter, r *http.Request) {
	UserID, err := cfg.validateJWT(r.Header)
	if err != nil {
		renderError(err, 401, rw)
		return
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	type parameters struct {
		Body string `json:"body"`
	}
	var params parameters
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	if len(params.Body) > 140 {
		renderError(fmt.Errorf("Chirp is too long"), 400, rw)
		return
	}
	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{Body: params.Body, UserID: UserID})
	if err != nil {
		renderError(err, 400, rw)
		return
	}
	rw.WriteHeader(201)
	data, err := json.Marshal(Chirp{ID: chirp.ID, Body: CleanChirp(chirp.Body), UserID: chirp.UserID, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt})
	_, _ = rw.Write(data)
}

func (cfg *apiConfig) handleWebhooks(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		renderError(err, 401, rw)
		return
	}
	if apiKey != cfg.polkaKey {
		renderError(fmt.Errorf("Invalid API key"), 401, rw)
		return
	}

	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}
	var params parameters
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		renderError(err, 400, rw)
		return
	}

	if params.Event != "user.upgraded" {
		rw.WriteHeader(204)
		return
	}

	user, err := cfg.dbQueries.UpgradeUserIsChirpyRed(r.Context(), params.Data.UserID)
	if err != nil && user != uuid.Nil {
		renderError(err, 404, rw)
		return
	}

	rw.WriteHeader(204)
}

func (cfg *apiConfig) handleMetrics(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(200)
	content := `<html>
	  <body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	  </body>
	</html>`
	if _, err := rw.Write([]byte(fmt.Sprintf(content, cfg.fileserverHits.Load()))); err != nil {
		fmt.Println(fmt.Errorf("Error writing response: %v", err))
	}
}

func (cfg *apiConfig) handleReset(rw http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		rw.WriteHeader(403)
		return
	}
	cfg.fileserverHits.Store(0)
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(200)
	if err := cfg.dbQueries.DeleteUsers(r.Context()); err != nil {
		fmt.Println(fmt.Errorf("Error deleting users: %v", err))
	}
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func CleanChirp(chirp string) string {
	const pattern1 = "kerfuffle"
	const pattern2 = "sharbert"
	const pattern3 = "fornax"
	const replacement = "****"
	words := strings.Split(chirp, " ")
	var result []string
	for _, word := range words {
		lower := strings.ToLower(word)
		if lower == pattern1 || lower == pattern2 || lower == pattern3 {
			result = append(result, replacement)
		} else {
			result = append(result, word)
		}
	}
	return strings.Join(result, " ")
}

func renderError(err error, status int, rw http.ResponseWriter) {
	rw.WriteHeader(status)
	resp := errResponse{Error: err.Error()}
	errData, _ := json.Marshal(resp)
	_, _ = rw.Write(errData)
}

func (cfg *apiConfig) validateJWT(h http.Header) (uuid.UUID, error) {
	bearerToken, err := auth.GetBearerToken(h)
	if err != nil {
		return uuid.UUID{}, err
	}
	return auth.ValidateJWT(bearerToken, cfg.jwtSecret)
}

func (cfg *apiConfig) getChirps(ctx context.Context, userID string) ([]database.Chirp, error) {
	if userID == "" {
		return cfg.dbQueries.GetChirps(ctx)
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return []database.Chirp{}, err
	}
	return cfg.dbQueries.GetChirpsByAuthor(ctx, userUUID)
}
