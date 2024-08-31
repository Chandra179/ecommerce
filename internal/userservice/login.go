package userservice

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/Chandra179/ecommerce/configs"
	"github.com/Chandra179/ecommerce/pkg/utils"

	"golang.org/x/oauth2"
)

var stateStore = struct {
	m map[string]bool
	sync.RWMutex
}{m: make(map[string]bool)}

type Login struct {
	GlOauthCfg *configs.Config
}

func NewLogin(cfg *configs.Config) *Login {
	return &Login{GlOauthCfg: cfg}
}

func (l *Login) HandleLogin() {
	oauth2Config := &oauth2.Config{
		ClientID:     l.GlOauthCfg.GoogleOauth.ClientID,
		ClientSecret: l.GlOauthCfg.GoogleOauth.ClientSecret,
		RedirectURL:  l.GlOauthCfg.GoogleOauth.RedirectURL,
		Scopes:       l.GlOauthCfg.GoogleOauth.Scopes,
		Endpoint:     l.GlOauthCfg.GoogleOauth.Endpoint,
	}

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// state shoulld be unique per request to prevent CSRF, need to validate state upon callback to ensure response is legitimate
		state, err := utils.GenerateRandomString(32)
		if err != nil {
			http.Error(w, "Error generating state", http.StatusInternalServerError)
			return
		}

		// Store the state in a map for verification in the callback (no need for lock)
		stateStore.m[state] = true
		authURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	})

	// TODO: handle state by using random bytes
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")

		// Verify the state
		stateStore.RLock()
		_, exists := stateStore.m[state]
		stateStore.RUnlock()

		if !exists {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// State is valid, remove it to prevent replay attacks
		stateStore.Lock()
		delete(stateStore.m, state)
		stateStore.Unlock()

		code := r.URL.Query().Get("code")
		token, err := oauth2Config.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
			return
		}

		fmt.Println(token)
		// Use the token to get user info or perform other actions
		// Example: Save token to session, make API calls, etc.
		http.Redirect(w, r, "/success", http.StatusSeeOther)
	})
}
