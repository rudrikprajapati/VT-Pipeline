package main

import (
	"vt-data-refresh/api"
	"vt-data-refresh/config"
	"vt-data-refresh/cron"
	"vt-data-refresh/db"

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
	if err != nil {
		panic("Failed to initialize Redis client: " + err.Error())
	}

	// Initialize and start cron service
	cronService := cron.NewCronService(cfg)
	cronService.Start()
	defer cronService.Stop()

	r := gin.Default()
	if err := r.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
		panic("Failed to set trusted proxies: " + err.Error())
	}
	api.SetupRoutes(r, dbConn, cfg)

	if err := r.Run(":" + cfg.Server.Port); err != nil {
		panic("Failed to start server: " + err.Error())
	}
}
