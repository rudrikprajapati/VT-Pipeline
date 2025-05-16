package services

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
	"vt-data-refresh/config"
	"vt-data-refresh/models"
	"vt-data-refresh/repositories"

	"github.com/jmoiron/sqlx"
)

type IPResult struct {
	IP    *models.IPAddress
	Error error
}

func FetchIPReport(ips []string, reportType string, db *sqlx.DB, cfg *config.Config) ([]*models.IPAddress, error) {
	results := make([]*models.IPAddress, 0)
	resultChan := make(chan IPResult)
	limiter := GetGlobalRateLimiter() // Use shared rate limiter

	// Process IPs concurrently with rate limiting
	var wg sync.WaitGroup
	for _, id := range ips {
		wg.Add(1)
		go func(ipID string) {
			defer wg.Done()

			// Wait for rate limiter
			limiter.Wait()

			// Process single IP
			ip, err := processSingleIP(ipID, reportType, db, cfg)
			resultChan <- IPResult{IP: ip, Error: err}
		}(id)
	}

	// Close results channel when all goroutines are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and errors
	var errors []error
	for result := range resultChan {
		if result.Error != nil {
			errors = append(errors, result.Error)
			log.Printf("Error processing IP: %v", result.Error)
			continue
		}
		results = append(results, result.IP)
	}

	// If all IPs failed, return error
	if len(errors) == len(ips) {
		return nil, fmt.Errorf("all IP processing failed: %v", errors[0])
	}

	return results, nil
}

func processSingleIP(id string, reportType string, db *sqlx.DB, cfg *config.Config) (*models.IPAddress, error) {
	log.Printf("Starting FetchIPReport for ID: %s, Type: %s", id, reportType)

	// Fetch from VirusTotal API
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", reportType, id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", cfg.VirusTotal.APIKey)

	client := &http.Client{}
	log.Printf("Making API request to VirusTotal for ID: %s", id)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making API request for ID %s: %v", id, err)
		return nil, err
	}
	defer resp.Body.Close()

	// Parse API response
	var vtResponse models.VirusTotalIPResponse
	err = json.NewDecoder(resp.Body).Decode(&vtResponse)
	if err != nil {
		log.Printf("Error decoding API response for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully decoded API response for ID: %s", id)

	// Begin transaction
	tx, err := db.Beginx()
	if err != nil {
		log.Printf("Error beginning transaction for ID %s: %v", id, err)
		return nil, err
	}
	defer tx.Rollback()

	// Convert timestamps
	var lastAnalysisDate, whoisDate, lastModificationDate *time.Time
	if vtResponse.Data.Attributes.LastAnalysisDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.LastAnalysisDate, 0)
		lastAnalysisDate = &t
	}
	if vtResponse.Data.Attributes.WhoisDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.WhoisDate, 0)
		whoisDate = &t
	}
	if vtResponse.Data.Attributes.LastModificationDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.LastModificationDate, 0)
		lastModificationDate = &t
	}

	// Get analysis stats
	harmless := vtResponse.Data.Attributes.LastAnalysisStats["harmless"]
	malicious := vtResponse.Data.Attributes.LastAnalysisStats["malicious"]
	suspicious := vtResponse.Data.Attributes.LastAnalysisStats["suspicious"]
	undetected := vtResponse.Data.Attributes.LastAnalysisStats["undetected"]
	timeout := vtResponse.Data.Attributes.LastAnalysisStats["timeout"]

	// Create IP object
	ip := &models.IPAddress{
		ID:                       id,
		Type:                     reportType,
		LastAnalysisDate:         lastAnalysisDate,
		ASN:                      &vtResponse.Data.Attributes.ASN,
		Reputation:               &vtResponse.Data.Attributes.Reputation,
		Country:                  &vtResponse.Data.Attributes.Country,
		ASOwner:                  &vtResponse.Data.Attributes.ASOwner,
		RegionalInternetRegistry: &vtResponse.Data.Attributes.RegionalInternetRegistry,
		Network:                  &vtResponse.Data.Attributes.Network,
		WhoisDate:                whoisDate,
		LastModificationDate:     lastModificationDate,
		Continent:                &vtResponse.Data.Attributes.Continent,
		HarmlessCount:            &harmless,
		MaliciousCount:           &malicious,
		SuspiciousCount:          &suspicious,
		UndetectedCount:          &undetected,
		TimeoutCount:             &timeout,
		CreatedAt:                time.Now(),
		UpdatedAt:                time.Now(),
	}

	// Save IP data
	if err := repositories.SaveIPAddress(tx, ip); err != nil {
		log.Printf("Error saving IP data for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved IP data for ID: %s", id)

	// Save IP details
	votesJSON, _ := json.Marshal(vtResponse.Data.Attributes.TotalVotes)
	details := &models.IPDetails{
		IPID:       id,
		Whois:      vtResponse.Data.Attributes.Whois,
		TotalVotes: votesJSON,
	}

	if err := repositories.SaveIPDetails(tx, details); err != nil {
		log.Printf("Error saving IP details for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved IP details for ID: %s", id)

	// Save tags and analysis results
	errChan := make(chan error, 2)
	var wg sync.WaitGroup

	// Save tags
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := repositories.SaveIPTags(tx, id, vtResponse.Data.Attributes.Tags); err != nil {
			log.Printf("Error saving tags for ID %s: %v", id, err)
			errChan <- err
			return
		}
		log.Printf("Successfully saved tags for ID: %s", id)
	}()

	// Save analysis results
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := repositories.SaveIPAnalysisResults(tx, id, vtResponse.Data.Attributes.LastAnalysisResults); err != nil {
			log.Printf("Error saving analysis results for ID %s: %v", id, err)
			errChan <- err
			return
		}
		log.Printf("Successfully saved analysis results for ID: %s", id)
	}()

	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully committed transaction for ID: %s", id)

	return ip, nil
}
