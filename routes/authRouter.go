package routes

import(
	"github.com/sameepshukla/jwt-go/controllers"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(incoming Routes *gin.Engine){
	incomingRoutes.POST("users/signup", controller.Signup())
	incomingRoutes.POST("users/login", controller.Login() )
}