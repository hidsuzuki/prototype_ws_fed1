package usecase

import "github.com/prototype-ws-fed1/idp/internal/domain/entity"

type IssueTokenUsecase interface {
	IssueToken(user *entity.User, tokenType, appliesTo string) (*entity.SecurityToken, error)
}
