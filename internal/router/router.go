package router

import (
	"encoding/json"
	"net/http"
)

func New() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", handleHealth)

	return mux
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
