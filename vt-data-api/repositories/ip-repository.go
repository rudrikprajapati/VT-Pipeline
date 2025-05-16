package repositories

import (
	"vt-data-api/models"

	"github.com/jmoiron/sqlx"
)

// GetIPAddress retrieves IP data from the main table
func GetIPAddress(id string, db *sqlx.DB) (*models.IPAddress, error) {
	var ip models.IPAddress
	err := db.Get(&ip, "SELECT * FROM ip_addresses WHERE id=$1", id)
	if err != nil {
		return nil, err
	}
	return &ip, nil
}
