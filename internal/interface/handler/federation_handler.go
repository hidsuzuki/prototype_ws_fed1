package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	domainusecase "github.com/prototype-ws-fed1/idp/internal/domain/usecase"
	"github.com/prototype-ws-fed1/idp/pkg/wsfed"
)

type FederationHandler struct {
	authUsecase  domainusecase.AuthenticateUsecase
	tokenUsecase domainusecase.IssueTokenUsecase
}

func NewFederationHandler(
	authUsecase domainusecase.AuthenticateUsecase,
	tokenUsecase domainusecase.IssueTokenUsecase,
) *FederationHandler {
	return &FederationHandler{
		authUsecase:  authUsecase,
		tokenUsecase: tokenUsecase,
	}
}

func (h *FederationHandler) HandlePassive(c *gin.Context) {
	req := wsfed.ParsePassiveRequest(c.Request.URL.Query())

	if req.WAAction == "wsignout1.0" {
		c.String(http.StatusOK, "<html><body>Signed out successfully.</body></html>")
		return
	}

	if req.WAAction != "wsignin1.0" {
		c.String(http.StatusBadRequest, "Invalid wa parameter")
		return
	}

	if c.Request.Method == http.MethodGet {
		h.renderLoginForm(c, req)
		return
	}

	h.handleLoginPost(c, req)
}

func (h *FederationHandler) renderLoginForm(c *gin.Context, req *wsfed.PassiveRequest) {
	html := `<!DOCTYPE html>
<html>
<head>
  <title>Sign In</title>
  <meta charset="UTF-8"/>
  <style>
    body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f0f0; }
    .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }
    h2 { margin-top: 0; color: #333; }
    input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }
    button { width: 100%; padding: 12px; background: #0078d4; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
    button:hover { background: #006cbf; }
    .error { color: red; margin-bottom: 10px; }
  </style>
</head>
<body>
  <div class="login-box">
    <h2>Sign In</h2>
    <form method="POST">
      <input type="hidden" name="wa" value="wsignin1.0"/>
      <input type="hidden" name="wtrealm" value="` + req.WTREALM + `"/>
      <input type="hidden" name="wreply" value="` + req.WREPLY + `"/>
      <input type="hidden" name="wctx" value="` + req.WCTX + `"/>
      <input type="text" name="username" placeholder="user@contoso.com" required/>
      <input type="password" name="password" placeholder="Password" required/>
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

func (h *FederationHandler) handleLoginPost(c *gin.Context, req *wsfed.PassiveRequest) {
	if req.WAAction == "" {
		req = wsfed.ParsePassiveRequest(c.Request.Form)
	}

	username := c.PostForm("username")
	password := c.PostForm("password")
	wctx := c.PostForm("wctx")
	wreply := c.PostForm("wreply")
	wtrealm := c.PostForm("wtrealm")

	if wreply == "" {
		wreply = req.WREPLY
	}
	if wctx == "" {
		wctx = req.WCTX
	}
	if wtrealm == "" {
		wtrealm = req.WTREALM
	}

	user, err := h.authUsecase.Authenticate(username, password)
	if err != nil {
		h.renderLoginFormWithError(c, req, "Invalid username or password")
		return
	}

	appliesTo := wtrealm
	if appliesTo == "" {
		appliesTo = "urn:federation:MicrosoftOnline"
	}

	token, err := h.tokenUsecase.IssueToken(user, "urn:oasis:names:tc:SAML:1.0:assertion", appliesTo)
	if err != nil {
		h.renderLoginFormWithError(c, req, "Token issuance failed")
		return
	}

	if wreply == "" {
		wreply = "https://login.microsoftonline.com/login.srf"
	}

	responseHTML := wsfed.BuildPassiveSignInResponse(token.XMLData, wctx, wreply, token.IssuedAt, token.ExpiresAt)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, responseHTML)
}

func (h *FederationHandler) renderLoginFormWithError(c *gin.Context, req *wsfed.PassiveRequest, errMsg string) {
	html := `<!DOCTYPE html>
<html>
<head>
  <title>Sign In</title>
  <meta charset="UTF-8"/>
  <style>
    body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f0f0; }
    .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }
    h2 { margin-top: 0; color: #333; }
    input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }
    button { width: 100%; padding: 12px; background: #0078d4; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
    button:hover { background: #006cbf; }
    .error { color: red; margin-bottom: 10px; }
  </style>
</head>
<body>
  <div class="login-box">
    <h2>Sign In</h2>
    <p class="error">` + errMsg + `</p>
    <form method="POST">
      <input type="hidden" name="wa" value="wsignin1.0"/>
      <input type="hidden" name="wtrealm" value="` + req.WTREALM + `"/>
      <input type="hidden" name="wreply" value="` + req.WREPLY + `"/>
      <input type="hidden" name="wctx" value="` + req.WCTX + `"/>
      <input type="text" name="username" placeholder="user@contoso.com" required/>
      <input type="password" name="password" placeholder="Password" required/>
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}
