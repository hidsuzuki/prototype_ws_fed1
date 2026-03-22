package usecase

import (
	"crypto/rsa"
	"time"

	"github.com/google/uuid"
	"github.com/prototype-ws-fed1/idp/internal/domain/entity"
	"github.com/prototype-ws-fed1/idp/pkg/saml"
)

type IssueTokenInteractor struct {
	issuerURL   string
	privateKey  *rsa.PrivateKey
	certPEM     []byte
	validHours  int
}

func NewIssueTokenInteractor(issuerURL string, privateKey *rsa.PrivateKey, certPEM []byte, validHours int) *IssueTokenInteractor {
	return &IssueTokenInteractor{
		issuerURL:  issuerURL,
		privateKey: privateKey,
		certPEM:    certPEM,
		validHours: validHours,
	}
}

func (i *IssueTokenInteractor) IssueToken(user *entity.User, tokenType, appliesTo string) (*entity.SecurityToken, error) {
	now := time.Now().UTC()
	expiry := now.Add(time.Duration(i.validHours) * time.Hour)
	tokenID := "_" + uuid.New().String()

	claims := []entity.Claim{
		{Type: entity.ClaimTypeUPN, Value: user.UPN},
		{Type: entity.ClaimTypeEmail, Value: user.Email},
		{Type: entity.ClaimTypeDisplayName, Value: user.DisplayName},
		{Type: entity.ClaimTypeObjectID, Value: user.ID},
		{Type: entity.ClaimTypeImmutableID, Value: user.ID},
		{Type: entity.ClaimTypeAuthMethod, Value: "urn:oasis:names:tc:SAML:1.0:am:password"},
		{Type: entity.ClaimTypeAuthInstant, Value: now.Format(time.RFC3339)},
	}

	xmlData, err := saml.BuildSAML11Assertion(saml.AssertionParams{
		ID:         tokenID,
		IssuerURL:  i.issuerURL,
		IssuedAt:   now,
		NotBefore:  now,
		NotOnOrAfter: expiry,
		User:       user,
		Claims:     claims,
		AppliesTo:  appliesTo,
		PrivateKey: i.privateKey,
		CertPEM:    i.certPEM,
	})
	if err != nil {
		return nil, err
	}

	return &entity.SecurityToken{
		ID:         tokenID,
		TokenType:  tokenType,
		IssuedAt:   now,
		ExpiresAt:  expiry,
		Issuer:     i.issuerURL,
		SubjectUPN: user.UPN,
		Claims:     claims,
		XMLData:    xmlData,
	}, nil
}
