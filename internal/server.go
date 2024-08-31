package internal

import (
	"fmt"
	"net/http"

	"github.com/Chandra179/ecommerce/configs"
	"github.com/Chandra179/ecommerce/pkg/oauth"
)

func StartServer() {
	config, err := configs.LoadConfig()
	if err != nil {
		fmt.Println("err")
	}
	googleOauth := oauth.NewGoogleOauth(config)
	googleOauth.OauthManagement()
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("err")
	}
}
