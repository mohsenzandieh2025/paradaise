package main

import (
	"context"
	"log"
	"time"

	"github.com/zandieh/paradise-panel/backend/internal/agentclient"
	"github.com/zandieh/paradise-panel/backend/internal/api"
	"github.com/zandieh/paradise-panel/backend/internal/config"
	"github.com/zandieh/paradise-panel/backend/internal/database"
	"github.com/zandieh/paradise-panel/backend/internal/models"
	"github.com/zandieh/paradise-panel/backend/internal/risk"
	"github.com/zandieh/paradise-panel/backend/internal/stats"
)

func main() {
	cfg := config.Load()
	db := database.Connect(cfg)

	re := risk.New(db)
	collector := stats.New(db, re, cfg.StatsInterval)

	pool := agentclient.NewPool(
		cfg.PanelCertPath, cfg.PanelKeyPath, cfg.CACertPath, 10*time.Second,
	)
	defer pool.Close()

	fetch := func() (map[string]stats.UserTraffic, error) {
		var nodes []models.Node
		db.Where("status = ?", "online").Find(&nodes)
		return pool.CollectAll(context.Background(), nodes, cfg.AgentPort), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go collector.Start(ctx, fetch)

	h := &api.Handler{DB: db, Cfg: cfg, AgentPool: pool}
	log.Printf("پنل پارادایس نت روی :%s بالا آمد", cfg.Port)
	if err := api.NewRouter(h).Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
