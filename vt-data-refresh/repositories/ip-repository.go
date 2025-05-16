package repositories

import (
	"vt-data-refresh/models"

	"github.com/jmoiron/sqlx"
)

// SaveIPAddress saves or updates IP data
func SaveIPAddress(tx *sqlx.Tx, ip *models.IPAddress) error {
	_, err := tx.NamedExec(`INSERT INTO ip_addresses (id, type, last_analysis_date, asn, reputation, country, as_owner, regional_internet_registry, network, whois_date, last_modification_date, continent, harmless_count, malicious_count, suspicious_count, undetected_count, timeout_count, created_at, updated_at)
                          VALUES (:id, :type, :last_analysis_date, :asn, :reputation, :country, :as_owner, :regional_internet_registry, :network, :whois_date, :last_modification_date, :continent, :harmless_count, :malicious_count, :suspicious_count, :undetected_count, :timeout_count, :created_at, :updated_at)
                          ON CONFLICT (id) DO UPDATE SET
                          type = EXCLUDED.type,
                          last_analysis_date = EXCLUDED.last_analysis_date,
                          asn = EXCLUDED.asn,
                          reputation = EXCLUDED.reputation,
                          country = EXCLUDED.country,
                          as_owner = EXCLUDED.as_owner,
                          regional_internet_registry = EXCLUDED.regional_internet_registry,
                          network = EXCLUDED.network,
                          whois_date = EXCLUDED.whois_date,
                          last_modification_date = EXCLUDED.last_modification_date,
                          continent = EXCLUDED.continent,
                          harmless_count = EXCLUDED.harmless_count,
                          malicious_count = EXCLUDED.malicious_count,
                          suspicious_count = EXCLUDED.suspicious_count,
                          undetected_count = EXCLUDED.undetected_count,
                          timeout_count = EXCLUDED.timeout_count,
                          updated_at = EXCLUDED.updated_at`, ip)
	return err
}

// SaveTags saves IP tags
func SaveIPTags(tx *sqlx.Tx, ipID string, tags []string) error {
	// Clear existing tags
	_, err := tx.Exec("DELETE FROM ip_tags WHERE ip_id=$1", ipID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := tx.Prepare(`INSERT INTO ip_tags (ip_id, tag)
                          VALUES ($1, $2)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert new tags
	for _, tag := range tags {
		_, err = stmt.Exec(ipID, tag)
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveAnalysisResults saves IP analysis results
func SaveIPAnalysisResults(tx *sqlx.Tx, ipID string, results map[string]struct {
	Category string `json:"category"`
	Result   string `json:"result"`
	Method   string `json:"method"`
}) error {
	// Clear existing results
	_, err := tx.Exec("DELETE FROM ip_analysis_results WHERE ip_id=$1", ipID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := tx.Prepare(`INSERT INTO ip_analysis_results (ip_id, engine_name, category, result, method)
                          VALUES ($1, $2, $3, $4, $5)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert new results
	for engine, result := range results {
		_, err = stmt.Exec(
			ipID,
			engine,
			result.Category,
			result.Result,
			result.Method)
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveDetails saves IP details
func SaveIPDetails(tx *sqlx.Tx, details *models.IPDetails) error {
	_, err := tx.NamedExec(`INSERT INTO ip_details (ip_id, whois, total_votes)
                          VALUES (:ip_id, :whois, :total_votes)
                          ON CONFLICT (ip_id) DO UPDATE SET
                          whois = EXCLUDED.whois,
                          total_votes = EXCLUDED.total_votes`, details)
	return err
}
