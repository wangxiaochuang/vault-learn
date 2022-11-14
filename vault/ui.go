package vault

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/wxc"
)

const (
	uiConfigKey          = "config"
	uiConfigPlaintextKey = "config_plaintext"
)

// p23
type UIConfig struct {
	l               sync.RWMutex
	physicalStorage physical.Backend
	barrierStorage  logical.Storage

	enabled        bool
	defaultHeaders http.Header
}

func NewUIConfig(enabled bool, physicalStorage physical.Backend, barrierStorage logical.Storage) *UIConfig {
	defaultHeaders := http.Header{}
	defaultHeaders.Set("Service-Worker-Allowed", "/")
	defaultHeaders.Set("X-Content-Type-Options", "nosniff")
	defaultHeaders.Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'unsafe-inline' 'self'; form-action  'none'; frame-ancestors 'none'; font-src 'self'")

	return &UIConfig{
		physicalStorage: physicalStorage,
		barrierStorage:  barrierStorage,
		enabled:         enabled,
		defaultHeaders:  defaultHeaders,
	}
}

func (c *UIConfig) Enabled() bool {
	c.l.RLock()
	defer c.l.RUnlock()
	return c.enabled
}

func (c *UIConfig) Headers(ctx context.Context) (http.Header, error) {
	c.l.RLock()
	defer c.l.RUnlock()

	config, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	if config != nil {
		headers = config.Headers
	}

	for k := range c.defaultHeaders {
		if headers.Get(k) == "" {
			v := c.defaultHeaders.Get(k)
			headers.Set(k, v)
		}
	}
	return headers, nil
}

func (c *UIConfig) HeaderKeys(ctx context.Context) ([]string, error) {
	c.l.RLock()
	defer c.l.RUnlock()

	config, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	var keys []string
	for k := range config.Headers {
		keys = append(keys, k)
	}
	return keys, nil
}

func (c *UIConfig) GetHeader(ctx context.Context, header string) ([]string, error) {
	c.l.RLock()
	defer c.l.RUnlock()

	config, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	value := config.Headers.Values(header)
	return value, nil
}

func (c *UIConfig) SetHeader(ctx context.Context, header string, values []string) error {
	c.l.Lock()
	defer c.l.Unlock()

	config, err := c.get(ctx)
	if err != nil {
		return err
	}
	if config == nil {
		config = &uiConfigEntry{
			Headers: http.Header{},
		}
	}

	// Clear custom header values before setting new
	config.Headers.Del(header)

	// Set new values
	for _, value := range values {
		config.Headers.Add(header, value)
	}
	return c.save(ctx, config)
}

// DeleteHeader deletes the header configuration for the given header
func (c *UIConfig) DeleteHeader(ctx context.Context, header string) error {
	c.l.Lock()
	defer c.l.Unlock()

	config, err := c.get(ctx)
	if err != nil {
		return err
	}
	if config == nil {
		return nil
	}

	config.Headers.Del(header)
	return c.save(ctx, config)
}

func (c *UIConfig) get(ctx context.Context) (*uiConfigEntry, error) {
	plaintextConfigRaw, err := c.physicalStorage.Get(ctx, uiConfigPlaintextKey)
	if err != nil {
		return nil, err
	}

	configRaw, uiConfigGetErr := c.barrierStorage.Get(ctx, uiConfigKey)
	if uiConfigGetErr != nil && !strings.Contains(uiConfigGetErr.Error(), ErrBarrierSealed.Error()) {
		return nil, uiConfigGetErr
	}
	if configRaw == nil {
		return nil, nil
	}
	wxc.P(plaintextConfigRaw)
	panic("not implement")
}

func (c *UIConfig) save(ctx context.Context, config *uiConfigEntry) error {
	panic("not implement")
}

type uiConfigEntry struct {
	Headers http.Header `json:"headers"`
}
