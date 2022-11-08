package serviceregistration

import (
	"sync"

	log "github.com/hashicorp/go-hclog"
)

type State struct {
	VaultVersion                                            string
	IsInitialized, IsSealed, IsActive, IsPerformanceStandby bool
}

type Factory func(config map[string]string, logger log.Logger, state State) (ServiceRegistration, error)

type ServiceRegistration interface {
	Run(shutdownCh <-chan struct{}, wait *sync.WaitGroup, redirectAddr string) error
	NotifyActiveStateChange(isActive bool) error
	NotifySealedStateChange(isSealed bool) error
	NotifyPerformanceStandbyStateChange(isStandby bool) error
	NotifyInitializedStateChange(isInitialized bool) error
}
