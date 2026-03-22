package entity

import "time"

type SecurityToken struct {
	ID         string
	TokenType  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Issuer     string
	SubjectUPN string
	Claims     []Claim
	XMLData    string
}
