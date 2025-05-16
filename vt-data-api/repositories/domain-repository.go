package repositories

import (
	"vt-data-api/models"

	"github.com/jmoiron/sqlx"
)

// GetDomain retrieves domain data from the main table
func GetDomain(id string, db *sqlx.DB) (*models.Domain, error) {
	var domain models.Domain
	err := db.Get(&domain, "SELECT * FROM domains WHERE id=$1", id)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}
