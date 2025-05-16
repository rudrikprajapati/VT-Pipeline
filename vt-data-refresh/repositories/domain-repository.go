package repositories

import (
	"vt-data-refresh/models"

	"github.com/jmoiron/sqlx"
)

// SaveDomain saves or updates domain data
func SaveDomain(tx *sqlx.Tx, domain *models.Domain) error {
	_, err := tx.NamedExec(`INSERT INTO domains (id, type, creation_date, expiration_date, last_analysis_date, reputation, registrar, tld, whois_date, harmless_count, malicious_count, suspicious_count, undetected_count, timeout_count, created_at, updated_at)
                          VALUES (:id, :type, :creation_date, :expiration_date, :last_analysis_date, :reputation, :registrar, :tld, :whois_date, :harmless_count, :malicious_count, :suspicious_count, :undetected_count, :timeout_count, :created_at, :updated_at)
                          ON CONFLICT (id) DO UPDATE SET
                          type = EXCLUDED.type,
                          creation_date = EXCLUDED.creation_date,
                          expiration_date = EXCLUDED.expiration_date,
                          last_analysis_date = EXCLUDED.last_analysis_date,
                          reputation = EXCLUDED.reputation,
                          registrar = EXCLUDED.registrar,
                          tld = EXCLUDED.tld,
                          whois_date = EXCLUDED.whois_date,
                          harmless_count = EXCLUDED.harmless_count,
                          malicious_count = EXCLUDED.malicious_count,
                          suspicious_count = EXCLUDED.suspicious_count,
                          undetected_count = EXCLUDED.undetected_count,
                          timeout_count = EXCLUDED.timeout_count,
                          updated_at = EXCLUDED.updated_at`, domain)
	return err
}

// SaveCategories saves domain categories
func SaveDomainCategories(tx *sqlx.Tx, domainID string, categories map[string]string) error {
	// Clear existing categories
	_, err := tx.Exec("DELETE FROM domain_categories WHERE domain_id=$1", domainID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := tx.Prepare(`INSERT INTO domain_categories (domain_id, engine_name, category)
                          VALUES ($1, $2, $3)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert new categories
	for engine, category := range categories {
		_, err = stmt.Exec(domainID, engine, category)
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveAnalysisResults saves domain analysis results
func SaveDomainAnalysisResults(tx *sqlx.Tx, domainID string, results map[string]struct {
	Category string `json:"category"`
	Result   string `json:"result"`
	Method   string `json:"method"`
}) error {
	// Clear existing results
	_, err := tx.Exec("DELETE FROM domain_analysis_results WHERE domain_id=$1", domainID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := tx.Prepare(`INSERT INTO domain_analysis_results (domain_id, engine_name, category, result, method)
                          VALUES ($1, $2, $3, $4, $5)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert new results
	for engine, result := range results {
		_, err = stmt.Exec(
			domainID,
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

// SaveDetails saves domain details
func SaveDomainDetails(tx *sqlx.Tx, details *models.DomainDetails) error {
	_, err := tx.NamedExec(`INSERT INTO domain_details (domain_id, last_dns_records, last_https_certificate, rdap, whois, popularity_ranks, total_votes)
                          VALUES (:domain_id, :last_dns_records, :last_https_certificate, :rdap, :whois, :popularity_ranks, :total_votes)
                          ON CONFLICT (domain_id) DO UPDATE SET
                          last_dns_records = EXCLUDED.last_dns_records,
                          last_https_certificate = EXCLUDED.last_https_certificate,
                          rdap = EXCLUDED.rdap,
                          whois = EXCLUDED.whois,
                          popularity_ranks = EXCLUDED.popularity_ranks,
                          total_votes = EXCLUDED.total_votes`, details)
	return err
}
