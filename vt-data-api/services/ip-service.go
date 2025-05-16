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

func FetchIPReport(id, reportType string, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) (*models.IPAddress, error) {
	log.Printf("Starting FetchIPReport for ID: %s, Type: %s", id, reportType)

	// Check Redis cache first
	cacheKey := fmt.Sprintf("ip:%s", id)
	cachedData, err := redisClient.Get(context.Background(), cacheKey)
	if err == nil && cachedData != "" {
		log.Printf("Redis cache hit for ID: %s", id)
		var ip models.IPAddress
		if err := json.Unmarshal([]byte(cachedData), &ip); err != nil {
			log.Printf("Error unmarshaling cached data for ID %s: %v", id, err)
			return nil, err
		}
		return &ip, nil
	}
	log.Printf("Redis cache miss for ID: %s, proceeding with API call", id)

	IPFromDB, err := repositories.GetIPAddress(id, db)

	if err != nil {
		log.Printf("Error fetching IP from DB: %v", err)
		return nil, err
	}

	if IPFromDB != nil {
		ipJSON, err := json.Marshal(IPFromDB)
		if err != nil {
			log.Printf("Error marshaling IP for cache: %v", err)
		} else {
			if err := redisClient.Set(context.Background(), cacheKey, ipJSON, time.Hour); err != nil {
				log.Printf("Error saving to Redis cache: %v", err)
			} else {
				log.Printf("Successfully saved to Redis cache for ID: %s", id)
			}
		}
		return IPFromDB, nil
	}

	return nil, err
}
