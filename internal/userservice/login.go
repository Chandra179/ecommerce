package userservice

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Chandra179/ecommerce/configs"

	"golang.org/x/oauth2"
)

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
		authURL := oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	})

	// TODO: handle state by using random bytes
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state != "state" {
			http.Error(w, "State does not match", http.StatusBadRequest)
			return
		}

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
