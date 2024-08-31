package oauth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Chandra179/ecommerce/configs"

	"golang.org/x/oauth2"
)

var oauthToken *oauth2.Token

type OAuthState struct {
	State    string
	Verifier string
}

// Mock in-memory state store (use a proper storage solution in production)
type StateStore struct {
	m map[string]OAuthState
	sync.RWMutex
}

var stateStore = StateStore{m: make(map[string]OAuthState)}

type GoogleOauth struct {
	GlOauthCfg *configs.Config
}

func NewGoogleOauth(cfg *configs.Config) *GoogleOauth {
	return &GoogleOauth{GlOauthCfg: cfg}
}

func (l *GoogleOauth) OauthManagement() {
	oauth2Config := &oauth2.Config{
		ClientID:     l.GlOauthCfg.GoogleOauth.ClientID,
		ClientSecret: l.GlOauthCfg.GoogleOauth.ClientSecret,
		RedirectURL:  l.GlOauthCfg.GoogleOauth.RedirectURL,
		Scopes:       l.GlOauthCfg.GoogleOauth.Scopes,
		Endpoint:     l.GlOauthCfg.GoogleOauth.Endpoint,
	}

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Generate a unique state to prevent CSRF attacks
		state := oauth2.GenerateVerifier()

		// Generate PKCE code verifier and challenge
		verifier := oauth2.GenerateVerifier()
		challenge := oauth2.S256ChallengeFromVerifier(verifier)

		// Store state and verifier
		stateStore.Lock()
		stateStore.m[state] = OAuthState{
			State:    state,
			Verifier: verifier,
		}
		stateStore.Unlock()

		// Create the authorization URL with PKCE challenge and state
		authURL := oauth2Config.AuthCodeURL(
			state,
			oauth2.AccessTypeOffline,
			oauth2.SetAuthURLParam("include_granted_scopes", "true"),
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")

		// Verify the state
		stateStore.RLock()
		oauthState, exists := stateStore.m[state]
		stateStore.RUnlock()

		if !exists {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// State is valid, remove it to prevent replay attacks
		stateStore.Lock()
		delete(stateStore.m, state)
		stateStore.Unlock()

		// Retrieve the authorization code from the callback URL
		code := r.URL.Query().Get("code")

		// Exchange the authorization code for tokens
		token, err := oauth2Config.Exchange(context.Background(), code, oauth2.VerifierOption(oauthState.Verifier))
		if err != nil {
			http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
			return
		}

		// Store the token in a global variable or context
		oauthToken = token
		http.Redirect(w, r, "/success", http.StatusSeeOther)
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		if oauthToken == nil {
			http.Error(w, "No token found", http.StatusBadRequest)
		}

		if oauthToken.Expiry.Before(time.Now()) {
			ts := oauth2Config.TokenSource(context.Background(), oauthToken)
			newToken, err := ts.Token()
			if err != nil {
				http.Error(w, "Failed to refresh token", http.StatusBadRequest)
			}
			oauthToken = newToken
		}

	})
}
