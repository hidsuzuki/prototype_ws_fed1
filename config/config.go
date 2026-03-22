package config

import (
	"os"
	"strconv"
)

type Config struct {
	ServerPort         string
	IssuerURL          string
	FederationDomain   string
	TokenValidityHours int
}

func Load() *Config {
	validHours := 8
	if v := os.Getenv("TOKEN_VALIDITY_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			validHours = n
		}
	}

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "https://sts.contoso.com"
	}

	domain := os.Getenv("FEDERATION_DOMAIN")
	if domain == "" {
		domain = "contoso.com"
	}

	return &Config{
		ServerPort:         port,
		IssuerURL:          issuerURL,
		FederationDomain:   domain,
		TokenValidityHours: validHours,
	}
}
