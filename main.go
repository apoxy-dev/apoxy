/*
Copyright 2023 Apoxy, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/apoxy-dev/apoxy/pkg/cmd"
)

func main() {
	// We send errors to Sentry to ensure the best possible experience for our users.
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              "https://4da486e8bfc297ebd07dea8a1419f5da@o4506619284815872.ingest.sentry.io/4506619287306240",
		TracesSampleRate: 1.0,
	})
	if err != nil {
		log.Fatalf("sentry.Init: %s", err)
	}
	defer sentry.Flush(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	// Intercept SIGINT and SIGTERM to ensure we clean up before exiting.
	// This is especially important for long-running commands.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
