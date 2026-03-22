package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	domainusecase "github.com/prototype-ws-fed1/idp/internal/domain/usecase"
	"github.com/prototype-ws-fed1/idp/pkg/wstrust"
)

const (
	trustNS2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	trustNS13   = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
)

type WSTrustHandler struct {
	authUsecase  domainusecase.AuthenticateUsecase
	tokenUsecase domainusecase.IssueTokenUsecase
}

func NewWSTrustHandler(
	authUsecase domainusecase.AuthenticateUsecase,
	tokenUsecase domainusecase.IssueTokenUsecase,
) *WSTrustHandler {
	return &WSTrustHandler{
		authUsecase:  authUsecase,
		tokenUsecase: tokenUsecase,
	}
}

func (h *WSTrustHandler) HandleUsernameMixed(trustVersion string) gin.HandlerFunc {
	return func(c *gin.Context) {
		req, err := wstrust.ParseSOAPRequest(c.Request.Body)
		if err != nil {
			c.Header("Content-Type", "application/soap+xml; charset=utf-8")
			c.String(http.StatusBadRequest, wstrust.BuildFaultResponse("wst:InvalidRequest", "Failed to parse request"))
			return
		}

		user, err := h.authUsecase.Authenticate(req.Username, req.Password)
		if err != nil {
			c.Header("Content-Type", "application/soap+xml; charset=utf-8")
			c.String(http.StatusUnauthorized, wstrust.BuildFaultResponse("wst:FailedAuthentication", "Authentication failed"))
			return
		}

		token, err := h.tokenUsecase.IssueToken(user, req.TokenType, req.AppliesTo)
		if err != nil {
			c.Header("Content-Type", "application/soap+xml; charset=utf-8")
			c.String(http.StatusInternalServerError, wstrust.BuildFaultResponse("wst:RequestFailed", "Token issuance failed"))
			return
		}

		var ns string
		if trustVersion == "2005" {
			ns = trustNS2005
		} else {
			ns = trustNS13
		}

		response := wstrust.BuildWSTrust13Response(
			token.XMLData,
			token.TokenType,
			req.AppliesTo,
			token.IssuedAt,
			token.ExpiresAt,
			ns,
		)

		c.Header("Content-Type", "application/soap+xml; charset=utf-8")
		c.String(http.StatusOK, response)
	}
}

func (h *WSTrustHandler) HandleWindowsTransport(trustVersion string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/soap+xml; charset=utf-8")
		c.String(http.StatusUnauthorized, wstrust.BuildFaultResponse(
			"wst:FailedAuthentication",
			"Windows Integrated Authentication is not supported in this environment",
		))
	}
}

func (h *WSTrustHandler) GetMEX(c *gin.Context) {
	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.String(http.StatusOK, buildMEXDocument(c.Request.Host))
}

func buildMEXDocument(host string) string {
	baseURL := "https://" + host
	return `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                  xmlns:wsp="http://www.w3.org/ns/ws-policy"
                  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
                  xmlns:wsa="http://www.w3.org/2005/08/addressing"
                  xmlns:wsam="http://www.w3.org/2007/05/addressing/metadata"
                  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap12/"
                  xmlns:tns="http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice"
                  xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                  xmlns:trust2005="http://schemas.xmlsoap.org/ws/2005/02/trust"
                  targetNamespace="http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice">

  <wsp:Policy wsu:Id="UserNameMixed_policy">
    <wsp:ExactlyOne>
      <wsp:All>
        <sp:TransportBinding xmlns:sp="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702">
          <wsp:Policy>
            <sp:TransportToken>
              <wsp:Policy>
                <sp:HttpsToken/>
              </wsp:Policy>
            </sp:TransportToken>
          </wsp:Policy>
        </sp:TransportBinding>
        <sp:SignedEncryptedSupportingTokens xmlns:sp="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702">
          <wsp:Policy>
            <sp:UsernameToken sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient">
              <wsp:Policy>
                <sp:WssUsernameToken10/>
              </wsp:Policy>
            </sp:UsernameToken>
          </wsp:Policy>
        </sp:SignedEncryptedSupportingTokens>
      </wsp:All>
    </wsp:ExactlyOne>
  </wsp:Policy>

  <wsdl:portType name="IWSTrust13Sync">
    <wsdl:operation name="Trust13Issue">
      <wsdl:input wsam:Action="http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue" message="tns:IWSTrust13Sync_Trust13Issue_InputMessage"/>
      <wsdl:output wsam:Action="http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Issue" message="tns:IWSTrust13Sync_Trust13Issue_OutputMessage"/>
    </wsdl:operation>
  </wsdl:portType>

  <wsdl:binding name="UserNameMixed_binding" type="tns:IWSTrust13Sync">
    <wsp:PolicyReference URI="#UserNameMixed_policy"/>
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="Trust13Issue">
      <soap:operation soapAction="http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>

  <wsdl:service name="SecurityTokenService">
    <wsdl:port name="UserNameMixed" binding="tns:UserNameMixed_binding">
      <soap:address location="` + baseURL + `/adfs/services/trust/13/usernamemixed"/>
    </wsdl:port>
    <wsdl:port name="UserNameMixed2005" binding="tns:UserNameMixed_binding">
      <soap:address location="` + baseURL + `/adfs/services/trust/2005/usernamemixed"/>
    </wsdl:port>
  </wsdl:service>

</wsdl:definitions>`
}
