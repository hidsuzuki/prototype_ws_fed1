package usecase

import "github.com/prototype-ws-fed1/idp/internal/domain/entity"

type AuthenticateUsecase interface {
	Authenticate(upn, password string) (*entity.User, error)
}
