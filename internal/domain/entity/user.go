package entity

type User struct {
	ID           string
	Username     string
	PasswordHash string
	Email        string
	DisplayName  string
	UPN          string
}
