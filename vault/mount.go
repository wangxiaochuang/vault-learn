package vault

import (
	"sync"
	"time"

	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/logical"
)

// p51
type ListingVisibilityType string

// p128
type MountTable struct {
	Type    string        `json:"type"`
	Entries []*MountEntry `json:"entries"`
}

// p310
type MountEntry struct {
	Table                 string            `json:"table"`                             // The table it belongs to
	Path                  string            `json:"path"`                              // Mount Path
	Type                  string            `json:"type"`                              // Logical backend Type. NB: This is the plugin name, e.g. my-vault-plugin, NOT plugin type (e.g. auth).
	Description           string            `json:"description"`                       // User-provided description
	UUID                  string            `json:"uuid"`                              // Barrier view UUID
	BackendAwareUUID      string            `json:"backend_aware_uuid"`                // UUID that can be used by the backend as a helper when a consistent value is needed outside of storage.
	Accessor              string            `json:"accessor"`                          // Unique but more human-friendly ID. Does not change, not used for any sensitive things (like as a salt, which the UUID sometimes is).
	Config                MountConfig       `json:"config"`                            // Configuration related to this mount (but not backend-derived)
	Options               map[string]string `json:"options"`                           // Backend options
	Local                 bool              `json:"local"`                             // Local mounts are not replicated or affected by replication
	SealWrap              bool              `json:"seal_wrap"`                         // Whether to wrap CSPs
	ExternalEntropyAccess bool              `json:"external_entropy_access,omitempty"` // Whether to allow external entropy source access
	Tainted               bool              `json:"tainted,omitempty"`                 // Set as a Write-Ahead flag for unmount/remount
	MountState            string            `json:"mount_state,omitempty"`             // The current mount state.  The only non-empty mount state right now is "unmounting"
	NamespaceID           string            `json:"namespace_id"`

	// namespace contains the populated namespace
	namespace *namespace.Namespace

	// synthesizedConfigCache is used to cache configuration values. These
	// particular values are cached since we want to get them at a point-in-time
	// without separately managing their locks individually. See SyncCache() for
	// the specific values that are being cached.
	synthesizedConfigCache sync.Map

	// version info
	Version        string `json:"plugin_version,omitempty"`         // The semantic version of the mounted plugin, e.g. v1.2.3.
	RunningVersion string `json:"running_plugin_version,omitempty"` // The semantic version of the mounted plugin as reported by the plugin.
	RunningSha256  string `json:"running_sha256,omitempty"`
}

type MountConfig struct {
	DefaultLeaseTTL           time.Duration         `json:"default_lease_ttl,omitempty" structs:"default_lease_ttl" mapstructure:"default_lease_ttl"` // Override for global default
	MaxLeaseTTL               time.Duration         `json:"max_lease_ttl,omitempty" structs:"max_lease_ttl" mapstructure:"max_lease_ttl"`             // Override for global default
	ForceNoCache              bool                  `json:"force_no_cache,omitempty" structs:"force_no_cache" mapstructure:"force_no_cache"`          // Override for global default
	AuditNonHMACRequestKeys   []string              `json:"audit_non_hmac_request_keys,omitempty" structs:"audit_non_hmac_request_keys" mapstructure:"audit_non_hmac_request_keys"`
	AuditNonHMACResponseKeys  []string              `json:"audit_non_hmac_response_keys,omitempty" structs:"audit_non_hmac_response_keys" mapstructure:"audit_non_hmac_response_keys"`
	ListingVisibility         ListingVisibilityType `json:"listing_visibility,omitempty" structs:"listing_visibility" mapstructure:"listing_visibility"`
	PassthroughRequestHeaders []string              `json:"passthrough_request_headers,omitempty" structs:"passthrough_request_headers" mapstructure:"passthrough_request_headers"`
	AllowedResponseHeaders    []string              `json:"allowed_response_headers,omitempty" structs:"allowed_response_headers" mapstructure:"allowed_response_headers"`
	TokenType                 logical.TokenType     `json:"token_type,omitempty" structs:"token_type" mapstructure:"token_type"`
	AllowedManagedKeys        []string              `json:"allowed_managed_keys,omitempty" mapstructure:"allowed_managed_keys"`

	// PluginName is the name of the plugin registered in the catalog.
	//
	// Deprecated: MountEntry.Type should be used instead for Vault 1.0.0 and beyond.
	PluginName string `json:"plugin_name,omitempty" structs:"plugin_name,omitempty" mapstructure:"plugin_name"`
}
