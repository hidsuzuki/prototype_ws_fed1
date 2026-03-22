package repository

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/prototype-ws-fed1/idp/internal/domain/entity"
	"golang.org/x/crypto/bcrypt"
)

type InMemoryUserRepository struct {
	mu    sync.RWMutex
	users map[string]*entity.User
}

func NewInMemoryUserRepository() (*InMemoryUserRepository, error) {
	repo := &InMemoryUserRepository{
		users: make(map[string]*entity.User),
	}

	testUsers := []struct {
		upn         string
		password    string
		displayName string
	}{
		{"testuser@contoso.com", "Password123!", "Test User"},
		{"admin@contoso.com", "Admin@456", "Administrator"},
	}

	for _, u := range testUsers {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		id := uuid.New().String()
		user := &entity.User{
			ID:           id,
			Username:     u.upn,
			PasswordHash: string(hash),
			Email:        u.upn,
			DisplayName:  u.displayName,
			UPN:          u.upn,
		}
		repo.users[u.upn] = user
	}

	return repo, nil
}

func (r *InMemoryUserRepository) FindByUPN(upn string) (*entity.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.users[upn]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (r *InMemoryUserRepository) FindByID(id string) (*entity.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}
