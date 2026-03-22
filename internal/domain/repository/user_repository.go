package repository

import "github.com/prototype-ws-fed1/idp/internal/domain/entity"

type UserRepository interface {
	FindByUPN(upn string) (*entity.User, error)
	FindByID(id string) (*entity.User, error)
}
