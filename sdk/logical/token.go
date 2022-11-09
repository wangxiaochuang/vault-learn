package logical

import (
	"time"

	"github.com/hashicorp/go-sockaddr"
)

type TokenType uint8

// p90
type TokenEntry struct {
	Type TokenType `json:"type" mapstructure:"type" structs:"type" sentinel:""`

	ID string `json:"id" mapstructure:"id" structs:"id" sentinel:""`

	ExternalID string `json:"-"`

	Accessor string `json:"accessor" mapstructure:"accessor" structs:"accessor" sentinel:""`

	Parent string `json:"parent" mapstructure:"parent" structs:"parent" sentinel:""`

	Policies []string `json:"policies" mapstructure:"policies" structs:"policies"`

	InlinePolicy string `json:"inline_policy" mapstructure:"inline_policy" structs:"inline_policy"`

	Path string `json:"path" mapstructure:"path" structs:"path"`

	Meta map[string]string `json:"meta" mapstructure:"meta" structs:"meta" sentinel:"meta"`

	InternalMeta map[string]string `json:"internal_meta" mapstructure:"internal_meta" structs:"internal_meta"`

	DisplayName string `json:"display_name" mapstructure:"display_name" structs:"display_name"`

	NumUses int `json:"num_uses" mapstructure:"num_uses" structs:"num_uses"`

	CreationTime int64 `json:"creation_time" mapstructure:"creation_time" structs:"creation_time" sentinel:""`

	TTL time.Duration `json:"ttl" mapstructure:"ttl" structs:"ttl" sentinel:""`

	ExplicitMaxTTL time.Duration `json:"explicit_max_ttl" mapstructure:"explicit_max_ttl" structs:"explicit_max_ttl" sentinel:""`

	Role string `json:"role" mapstructure:"role" structs:"role"`

	Period time.Duration `json:"period" mapstructure:"period" structs:"period" sentinel:""`

	DisplayNameDeprecated    string        `json:"DisplayName" mapstructure:"DisplayName" structs:"DisplayName" sentinel:""`
	NumUsesDeprecated        int           `json:"NumUses" mapstructure:"NumUses" structs:"NumUses" sentinel:""`
	CreationTimeDeprecated   int64         `json:"CreationTime" mapstructure:"CreationTime" structs:"CreationTime" sentinel:""`
	ExplicitMaxTTLDeprecated time.Duration `json:"ExplicitMaxTTL" mapstructure:"ExplicitMaxTTL" structs:"ExplicitMaxTTL" sentinel:""`

	EntityID string `json:"entity_id" mapstructure:"entity_id" structs:"entity_id"`

	NoIdentityPolicies bool `json:"no_identity_policies" mapstructure:"no_identity_policies" structs:"no_identity_policies"`

	BoundCIDRs []*sockaddr.SockAddrMarshaler `json:"bound_cidrs" sentinel:""`

	NamespaceID string `json:"namespace_id" mapstructure:"namespace_id" structs:"namespace_id" sentinel:""`

	CubbyholeID string `json:"cubbyhole_id" mapstructure:"cubbyhole_id" structs:"cubbyhole_id" sentinel:""`
}
