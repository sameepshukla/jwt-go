package controllers

import (
"context"
"fmt"
"log"
"strconv"
"net/http"
"time"
"github.com/gin-gonic/gin"
"github.com/sameepshukla/jwt-go/helpers"
"github.com/go-playground/validator/v10"
"github.com/sameepshukla/jwt-go/helpers"
"github.com/sameepshukla/jwt-go/models"
"golang.com/x/crypto/bcrypt"
"go.mongodb.org/mongo-driver/bson"
"go.mongodb.org/mongo-driver/bson/primitive"
"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()


func HashPassword(password string) string{
	bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil{
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string){
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email or the password is incorrect")
		check = false 
	}

	return check, msg
}

func Signup()gin.HandlerFunc{
	return fun(c *gin.Context){
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":validationErr.Error()})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil{
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error":"error occurred while checking the Email"})
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		count, err := userCollection.CountDocuments(ctx, bson.M{"phone":user.Phone})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error":"error occurred while checking the Phone Number"})
		}

	if count >0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error":"This phone or email does not exists..."})
	}
	user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.ID = primitive.NewObjectID()
	user.User_id = user.ID.Hex()
	token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name. *user.Last_name, *user.User_type, *user.User_id)
	user.Token = &token
	user.Refresh_token = &refreshToken
	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	if insertErr != nil {
		msg:= fmt.Sprintf("USer Item was not created")
		c.JSON(http.StatusInternalServerError, gin.H("error":msg))
		return
	}
	defer cancel()
	c.JSON(http.StatusOk, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc{
	return func (c *gin.Context){
		var ctx, cancel = context.WithTimeout(context.Background())
		var user models.User
		var foundUser models.User 

		if err := c.BindJSON(&user); err  != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error":"email or password incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return 
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error":"user not found"})
		}
		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_id, *foundUser.User_type)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id":foundUser.User_id}).Decode(&foundUser)

		 if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()})
			return
		 }
		 c.JSON(http.StatusOk, foundUser)
	}
}

func GetUsers() gin.HandlerFunc{
	return func(c *gin.Context){
		helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), )

		strv.Atoi(c.Query("recondPerPage"))
		if err != nil || recondPerPage <1 {
			recondPerPage = 10
		}
		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page <1 {
			page = 1
		}

		startIIndex := (page -1) * recondPerPage
		startIIndex, err =strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{{"_id", bson.D{{"_id", "null"}}}, {"total_count", bson.D{{"$sum", 1}}}, {"data", bson.D{{"$push", "$$ROOT"}}}}}}
		projectStage := bson.D{
			{"$project", bson.D}{
				{"_id", 0}, {"total_count", 1}, {"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recondPerPage}}}},
			}
		}
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage
		})
		defer cancel()
		if err != nil{
			c.JSON{http.StatusInternalServerError, gin.H{"error": "error occured while listing items"}}
		}
		var allUsers []bson.M 
		if err = result.All(ctx, &allusers); err!=nil{
			log.Fatal(err)
		}
		c.JSON(http.StatusOk, allusers[0])
	}
}

func GetUser() gin.HandlerFunc{
	return func(c *gin.Context){
		userId := c.Param("user_id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err :=  userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user) 
		defer cancel()
		if err != nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()} )
		}
		c.JSON(http.StatusOk, user)
	}
}