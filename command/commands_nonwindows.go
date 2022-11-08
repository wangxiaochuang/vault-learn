//go:build !windows

package command

import (
	"os"
	"os/signal"
	"syscall"
)

func MakeSigUSR2Ch() chan struct{} {
	resultCh := make(chan struct{})

	signalCh := make(chan os.Signal, 4)
	signal.Notify(signalCh, syscall.SIGUSR2)
	go func() {
		for {
			<-signalCh
			resultCh <- struct{}{}
		}
	}()
	return resultCh
}
