package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/prototype-ws-fed1/idp/internal/domain/entity"
)

type AssertionParams struct {
	ID           string
	IssuerURL    string
	IssuedAt     time.Time
	NotBefore    time.Time
	NotOnOrAfter time.Time
	User         *entity.User
	Claims       []entity.Claim
	AppliesTo    string
	PrivateKey   *rsa.PrivateKey
	CertPEM      []byte
}

type samlAssertion struct {
	XMLName            xml.Name `xml:"saml:Assertion"`
	SamlNS             string   `xml:"xmlns:saml,attr"`
	AssertionID        string   `xml:"AssertionID,attr"`
	Issuer             string   `xml:"Issuer,attr"`
	IssueInstant       string   `xml:"IssueInstant,attr"`
	MajorVersion       string   `xml:"MajorVersion,attr"`
	MinorVersion       string   `xml:"MinorVersion,attr"`
	Conditions         samlConditions
	AttributeStatement samlAttributeStatement
	AuthnStatement     samlAuthnStatement `xml:"saml:AuthenticationStatement"`
}

type samlConditions struct {
	XMLName                    xml.Name `xml:"saml:Conditions"`
	NotBefore                  string   `xml:"NotBefore,attr"`
	NotOnOrAfter               string   `xml:"NotOnOrAfter,attr"`
	AudienceRestriction        samlAudienceRestriction
}

type samlAudienceRestriction struct {
	XMLName  xml.Name `xml:"saml:AudienceRestrictionCondition"`
	Audience string   `xml:"saml:Audience"`
}

type samlAttributeStatement struct {
	XMLName    xml.Name        `xml:"saml:AttributeStatement"`
	Subject    samlSubject
	Attributes []samlAttribute `xml:"saml:Attribute"`
}

type samlSubject struct {
	XMLName             xml.Name `xml:"saml:Subject"`
	NameIdentifier      samlNameIdentifier
	SubjectConfirmation samlSubjectConfirmation
}

type samlNameIdentifier struct {
	XMLName xml.Name `xml:"saml:NameIdentifier"`
	Format  string   `xml:"Format,attr"`
	Value   string   `xml:",chardata"`
}

type samlSubjectConfirmation struct {
	XMLName            xml.Name `xml:"saml:SubjectConfirmation"`
	ConfirmationMethod string   `xml:"saml:ConfirmationMethod"`
}

type samlAttribute struct {
	XMLName            xml.Name `xml:"saml:Attribute"`
	AttributeName      string   `xml:"AttributeName,attr"`
	AttributeNamespace string   `xml:"AttributeNamespace,attr"`
	Values             []string `xml:"saml:AttributeValue"`
}

type samlAuthnStatement struct {
	XMLName              xml.Name `xml:"saml:AuthenticationStatement"`
	AuthenticationMethod string   `xml:"AuthenticationMethod,attr"`
	AuthenticationInstant string  `xml:"AuthenticationInstant,attr"`
	Subject              samlSubject
}

func BuildSAML11Assertion(p AssertionParams) (string, error) {
	immutableID := base64.StdEncoding.EncodeToString([]byte(p.User.ID))

	authnInstant := p.IssuedAt.Format("2006-01-02T15:04:05Z")

	attributes := []samlAttribute{
		{
			AttributeName:      "UPN",
			AttributeNamespace: "http://schemas.xmlsoap.org/claims",
			Values:             []string{p.User.UPN},
		},
		{
			AttributeName:      "ImmutableID",
			AttributeNamespace: "http://schemas.microsoft.com/LiveID/Federation/2008/05",
			Values:             []string{immutableID},
		},
	}

	subject := samlSubject{
		NameIdentifier: samlNameIdentifier{
			Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
			Value:  immutableID,
		},
		SubjectConfirmation: samlSubjectConfirmation{
			ConfirmationMethod: "urn:oasis:names:tc:SAML:1.0:cm:bearer",
		},
	}

	assertion := samlAssertion{
		SamlNS:       "urn:oasis:names:tc:SAML:1.0:assertion",
		AssertionID:  p.ID,
		Issuer:       p.IssuerURL + "/adfs/services/trust",
		IssueInstant: p.IssuedAt.Format("2006-01-02T15:04:05Z"),
		MajorVersion: "1",
		MinorVersion: "1",
		Conditions: samlConditions{
			NotBefore:    p.NotBefore.Format("2006-01-02T15:04:05Z"),
			NotOnOrAfter: p.NotOnOrAfter.Format("2006-01-02T15:04:05Z"),
			AudienceRestriction: samlAudienceRestriction{
				Audience: p.AppliesTo,
			},
		},
		AttributeStatement: samlAttributeStatement{
			Subject:    subject,
			Attributes: attributes,
		},
		AuthnStatement: samlAuthnStatement{
			AuthenticationMethod:  "urn:oasis:names:tc:SAML:1.0:am:password",
			AuthenticationInstant: authnInstant,
			Subject:               subject,
		},
	}

	assertionXML, err := xml.Marshal(assertion)
	if err != nil {
		return "", fmt.Errorf("failed to marshal assertion: %w", err)
	}

	signedXML, err := signXML(string(assertionXML), p.ID, p.PrivateKey, p.CertPEM)
	if err != nil {
		return "", fmt.Errorf("failed to sign assertion: %w", err)
	}

	return signedXML, nil
}

func signXML(xmlStr, referenceID string, privateKey *rsa.PrivateKey, certPEM []byte) (string, error) {
	certBase64 := extractCertBase64(certPEM)

	digestInput := canonicalizeXML(xmlStr)
	digestBytes := sha256.Sum256([]byte(digestInput))
	digestValue := base64.StdEncoding.EncodeToString(digestBytes[:])

	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
			`<ds:Reference URI="#%s">` +
			`<ds:Transforms>` +
			`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
			`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
			`</ds:Transforms>` +
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
			`<ds:DigestValue>%s</ds:DigestValue>` +
			`</ds:Reference>` +
			`</ds:SignedInfo>`,
		referenceID, digestValue,
	)

	signedInfoBytes := sha256.Sum256([]byte(signedInfo))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, signedInfoBytes[:])
	if err != nil {
		return "", err
	}
	sigValue := base64.StdEncoding.EncodeToString(sigBytes)

	thumbprintBytes := sha1.Sum([]byte(certBase64))
	_ = thumbprintBytes

	signature := fmt.Sprintf(
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
			`%s` +
			`<ds:SignatureValue>%s</ds:SignatureValue>` +
			`<ds:KeyInfo>` +
			`<ds:X509Data>` +
			`<ds:X509Certificate>%s</ds:X509Certificate>` +
			`</ds:X509Data>` +
			`</ds:KeyInfo>` +
			`</ds:Signature>`,
		signedInfo, sigValue, certBase64,
	)

	insertIdx := strings.Index(xmlStr, ">")
	if insertIdx == -1 {
		return xmlStr + signature, nil
	}

	return xmlStr[:insertIdx+1] + signature + xmlStr[insertIdx+1:], nil
}

func canonicalizeXML(xmlStr string) string {
	return xmlStr
}

func extractCertBase64(certPEM []byte) string {
	certStr := string(certPEM)
	certStr = strings.ReplaceAll(certStr, "-----BEGIN CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "-----END CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "\n", "")
	certStr = strings.ReplaceAll(certStr, "\r", "")
	return strings.TrimSpace(certStr)
}
