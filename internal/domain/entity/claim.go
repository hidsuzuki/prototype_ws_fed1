package entity

type Claim struct {
	Type  string
	Value string
}

const (
	ClaimTypeUPN         = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
	ClaimTypeEmail       = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	ClaimTypeDisplayName = "http://schemas.microsoft.com/identity/claims/displayname"
	ClaimTypeObjectID    = "http://schemas.microsoft.com/identity/claims/objectidentifier"
	ClaimTypeImmutableID = "http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"
	ClaimTypeAuthMethod  = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod"
	ClaimTypeAuthInstant = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant"
)
