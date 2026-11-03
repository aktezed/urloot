package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/aktezed/urloot/pkg/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	options := runner.ParseOptions()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	r, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	defer func() { _ = r.Close() }()

	if err := r.Run(ctx); err != nil {
		_ = r.Close()
		gologger.Fatal().Msgf("Execution failed: %s\n", err)
	}
}
