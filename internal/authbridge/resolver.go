package authbridge

import (
	"context"
	"database/sql"

	"lore-monorepo/internal/permission"
	"lore-monorepo/internal/user"
)

// UserDirectory adapts the user package to Directory.
type UserDirectory struct {
	Get func(ctx context.Context, id int64) (*user.User, error)
}

func (d UserDirectory) GetByID(ctx context.Context, id int64) (*user.User, error) {
	return d.Get(ctx, id)
}

// StoreResolver reads module_permissions. It does not grant every repository.
type StoreResolver struct {
	List func(ctx context.Context, userID int64) ([]string, error)
}

func (s StoreResolver) Repositories(ctx context.Context, userID int64) ([]string, error) {
	return s.List(ctx, userID)
}

func (s StoreResolver) Allows(ctx context.Context, userID int64, repositoryID string) (bool, error) {
	repos, err := s.List(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, id := range repos {
		if id == repositoryID {
			return true, nil
		}
	}
	return false, nil
}

// NewStoreResolver asks the permission service for active module repositories.
// The parent repository is not included. read and write both become Lore access;
// Lore 0.10.1 cannot enforce read as a separate mode.
func NewStoreResolver(db *sql.DB) StoreResolver {
	svc := permission.Service{DB: db}
	return StoreResolver{List: func(ctx context.Context, userID int64) ([]string, error) {
		if db == nil {
			return nil, context.Canceled
		}
		return svc.RepositoryIDs(ctx, userID)
	}}
}
