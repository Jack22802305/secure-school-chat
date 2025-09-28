package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"discord-clone/internal/server"
)

func main() {
	var (
		httpPort = flag.String("http", "8080", "HTTP server port")
		udpPort  = flag.String("udp", "8081", "UDP server port")
		dbPath   = flag.String("db", "discord.db", "Database file path")
	)
	flag.Parse()

	// Initialize the server
	srv, err := server.NewServer(*httpPort, *udpPort, *dbPath)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Start the server
	go func() {
		log.Printf("Starting HTTP server on port %s", *httpPort)
		log.Printf("Starting UDP server on port %s", *udpPort)
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server failed:", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	srv.Shutdown()
}

