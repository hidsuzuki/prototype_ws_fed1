package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prototype-ws-fed1/idp/internal/infrastructure/crypto"
)

type MetadataHandler struct {
	issuerURL   string
	certManager *crypto.CertificateManager
}

func NewMetadataHandler(issuerURL string, certManager *crypto.CertificateManager) *MetadataHandler {
	return &MetadataHandler{
		issuerURL:   issuerURL,
		certManager: certManager,
	}
}

func (h *MetadataHandler) GetFederationMetadata(c *gin.Context) {
	certDER := h.certManager.CertBase64DER()
	certBase64 := base64.StdEncoding.EncodeToString(certDER)

	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"
                  xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706"
                  entityID="%s/adfs/services/trust">
  <RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"
                  xsi:type="fed:SecurityTokenServiceType"
                  protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <fed:ClaimTypesOffered>
      <auth:ClaimType Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" Optional="true">
        <auth:DisplayName>UPN</auth:DisplayName>
      </auth:ClaimType>
      <auth:ClaimType Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" Optional="true">
        <auth:DisplayName>Email address</auth:DisplayName>
      </auth:ClaimType>
      <auth:ClaimType Uri="http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID" Optional="false">
        <auth:DisplayName>ImmutableID</auth:DisplayName>
      </auth:ClaimType>
    </fed:ClaimTypesOffered>
    <fed:PassiveRequestorEndpoint>
      <EndpointReference xmlns="http://www.w3.org/2005/08/addressing">
        <Address>%s/adfs/ls</Address>
      </EndpointReference>
    </fed:PassiveRequestorEndpoint>
    <fed:SecurityTokenServiceEndpoint>
      <EndpointReference xmlns="http://www.w3.org/2005/08/addressing">
        <Address>%s/adfs/services/trust/13/usernamemixed</Address>
      </EndpointReference>
    </fed:SecurityTokenServiceEndpoint>
    <fed:SecurityTokenServiceEndpoint>
      <EndpointReference xmlns="http://www.w3.org/2005/08/addressing">
        <Address>%s/adfs/services/trust/2005/usernamemixed</Address>
      </EndpointReference>
    </fed:SecurityTokenServiceEndpoint>
  </RoleDescriptor>
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
                    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="%s/adfs/ls"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="%s/adfs/ls"/>
  </IDPSSODescriptor>
</EntityDescriptor>`,
		h.issuerURL,
		certBase64,
		h.issuerURL,
		h.issuerURL,
		h.issuerURL,
		certBase64,
		h.issuerURL,
		h.issuerURL,
	)

	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.String(http.StatusOK, metadata)
}
