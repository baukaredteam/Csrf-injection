package main

import (
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const (
	csrfKey               string = "csrf_token"
	userSessionCookieName        = "SESSION_ID"
	usersSessionTime             = 60 * 60 * 24
)

type User struct {
	Login     string
	MasterKey int
}

var (
	store UsersStore

	ErrNotFound = errors.New("not found")
)

func main() {
	gob.Register(UserSession{})

	store = UsersStore{}
	store.init()

	r := gin.Default()
	gin.SetMode(gin.DebugMode)
	r.LoadHTMLGlob("views/*")

	cookiesStore := cookie.NewStore([]byte("secret"))
	cookiesStore.Options(sessions.Options{MaxAge: usersSessionTime}) // expire in a day
	r.Use(sessions.Sessions(userSessionCookieName, cookiesStore))
	r.Use(csrfMiddleware(func(c *gin.Context) string {
		return c.Request.FormValue("csrf_token")
	}))

	r.GET("/logout", logout)
	r.GET("/", index)
	r.POST("/login", login)
	r.GET("/accounts", getAccount)
	r.POST("/accounts", setAccountInfo)

	r.Run(":8080")
}

func index(c *gin.Context) {
	if sessionExist(c) {
		c.Redirect(303, "/accounts")
		return
	}
	token := newToken()
	session := sessions.Default(c)
	session.Set(csrfKey, token)
	session.Save()
	c.HTML(http.StatusOK, "index_v2.html", gin.H{
		"csrf": token,
	})
}

func getAccount(c *gin.Context) {
	if !sessionExist(c) {
		c.Redirect(303, "/")
		return
	}

	user, _ := store.get(sessionUserSession(c).Login)
	token := newToken()
	session := sessions.Default(c)
	session.Set(csrfKey, token)
	session.Save()
	c.HTML(http.StatusOK, "accounts.html", gin.H{
		"name":      user.Login,
		"masterKey": user.MasterKey,
		"csrf":      token,
	})
}
