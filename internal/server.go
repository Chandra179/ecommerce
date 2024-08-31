package internal

import (
	"fmt"
	"net/http"

	"github.com/Chandra179/ecommerce/configs"
	"github.com/Chandra179/ecommerce/internal/userservice"
)

func StartServer() {
	config, err := configs.LoadConfig()
	if err != nil {
		fmt.Println("err")
	}
	login := userservice.NewLogin(config)
	login.HandleLogin()
	http.ListenAndServe(":8080", nil)
}
