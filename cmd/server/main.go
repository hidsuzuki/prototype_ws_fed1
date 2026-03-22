package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/prototype-ws-fed1/idp/config"
	"github.com/prototype-ws-fed1/idp/internal/infrastructure/crypto"
	infrarepo "github.com/prototype-ws-fed1/idp/internal/infrastructure/repository"
	"github.com/prototype-ws-fed1/idp/internal/interface/handler"
	"github.com/prototype-ws-fed1/idp/internal/usecase"
)

func main() {
	cfg := config.Load()

	certManager, err := crypto.NewCertificateManager(cfg.FederationDomain)
	if err != nil {
		log.Fatalf("failed to initialize certificate manager: %v", err)
	}

	userRepo, err := infrarepo.NewInMemoryUserRepository()
	if err != nil {
		log.Fatalf("failed to initialize user repository: %v", err)
	}

	authInteractor := usecase.NewAuthenticateInteractor(userRepo)
	tokenInteractor := usecase.NewIssueTokenInteractor(
		cfg.IssuerURL,
		certManager.PrivateKey,
		certManager.CertPEM,
		cfg.TokenValidityHours,
	)

	metadataHandler := handler.NewMetadataHandler(cfg.IssuerURL, certManager)
	federationHandler := handler.NewFederationHandler(authInteractor, tokenInteractor)
	wstrustHandler := handler.NewWSTrustHandler(authInteractor, tokenInteractor)

	r := gin.Default()

	r.GET("/FederationMetadata/2007-06/FederationMetadata.xml", metadataHandler.GetFederationMetadata)

	r.GET("/adfs/ls", federationHandler.HandlePassive)
	r.POST("/adfs/ls", federationHandler.HandlePassive)

	r.GET("/adfs/services/trust/mex", wstrustHandler.GetMEX)

	r.POST("/adfs/services/trust/2005/usernamemixed", wstrustHandler.HandleUsernameMixed("2005"))
	r.POST("/adfs/services/trust/13/usernamemixed", wstrustHandler.HandleUsernameMixed("13"))

	r.POST("/adfs/services/trust/2005/windowstransport", wstrustHandler.HandleWindowsTransport("2005"))
	r.POST("/adfs/services/trust/13/windowstransport", wstrustHandler.HandleWindowsTransport("13"))

	log.Printf("Starting IdP server on port %s", cfg.ServerPort)
	log.Printf("Issuer URL: %s", cfg.IssuerURL)
	log.Printf("Federation Domain: %s", cfg.FederationDomain)

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
