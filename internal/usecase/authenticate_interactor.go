package usecase

import (
	"errors"

	"github.com/prototype-ws-fed1/idp/internal/domain/entity"
	domainrepo "github.com/prototype-ws-fed1/idp/internal/domain/repository"
	"golang.org/x/crypto/bcrypt"
)

type AuthenticateInteractor struct {
	userRepo domainrepo.UserRepository
}

func NewAuthenticateInteractor(userRepo domainrepo.UserRepository) *AuthenticateInteractor {
	return &AuthenticateInteractor{userRepo: userRepo}
}

func (a *AuthenticateInteractor) Authenticate(upn, password string) (*entity.User, error) {
	user, err := a.userRepo.FindByUPN(upn)
	if err != nil {
		return nil, errors.New("authentication failed")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("authentication failed")
	}

	return user, nil
}
