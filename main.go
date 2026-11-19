package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/13cast/assetwatch/cmd"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
