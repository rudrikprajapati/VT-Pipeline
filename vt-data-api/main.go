package main

import (
	"vt-data-api/api"
	"vt-data-api/config"
	"vt-data-api/db"
	"vt-data-api/redis"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	// Initialize database connection
	dbConn := db.InitDB(cfg.Database.URL)

	// Initialize Redis client
	redisClient, err := redis.NewRedisClient(cfg.Redis.URL, cfg.Redis.Password)
	if err != nil {
		panic("Failed to initialize Redis client: " + err.Error())
	}
	defer redisClient.Close()

	r := gin.Default()
	if err := r.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
		panic("Failed to set trusted proxies: " + err.Error())
	}
	api.SetupRoutes(r, dbConn, redisClient, cfg)

	if err := r.Run(":" + cfg.Server.Port); err != nil {
		panic("Failed to start server: " + err.Error())
	}
}
