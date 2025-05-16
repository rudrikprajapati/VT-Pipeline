package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"vt-data-api/config"
	"vt-data-api/models"
	"vt-data-api/redis"
	"vt-data-api/repositories"

	"github.com/jmoiron/sqlx"
)

func FetchDomainVTReport(id, reportType string, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) (*models.Domain, error) {
	log.Printf("Starting FetchVTReport for ID: %s, Type: %s", id, reportType)

	// Check Redis cache first
	cacheKey := fmt.Sprintf("domain:%s", id)
	cachedData, err := redisClient.Get(context.Background(), cacheKey)
	if err == nil && cachedData != "" {
		log.Printf("Redis cache hit for ID: %s", id)
		var domain models.Domain
		if err := json.Unmarshal([]byte(cachedData), &domain); err != nil {
			log.Printf("Error unmarshaling cached data for ID %s: %v", id, err)
			return nil, err
		}
		return &domain, nil
	}
	log.Printf("Redis cache miss for ID: %s, proceeding with API call", id)

	domainFromDB, err := repositories.GetDomain(id, db)

	if err != nil {
		log.Printf("Error fetching domain from DB: %v", err)
		return nil, err
	}

	if domainFromDB != nil {
		domainJSON, err := json.Marshal(domainFromDB)
		if err != nil {
			log.Printf("Error marshaling domain for cache: %v", err)
		} else {
			if err := redisClient.Set(context.Background(), cacheKey, domainJSON, time.Hour); err != nil {
				log.Printf("Error saving to Redis cache: %v", err)
			} else {
				log.Printf("Successfully saved to Redis cache for ID: %s", id)
			}
		}
		return domainFromDB, nil
	}

	return nil, err
}
