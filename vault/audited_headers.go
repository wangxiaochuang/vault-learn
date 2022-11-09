package vault

import "sync"

type auditedHeaderSettings struct {
	HMAC bool `json:"hmac"`
}

// p28
type AuditedHeadersConfig struct {
	Headers map[string]*auditedHeaderSettings

	view *BarrierView
	sync.RWMutex
}
