package namespace

type contextValues struct{}

type Namespace struct {
	ID             string            `json:"id" mapstructure:"id"`
	Path           string            `json:"path" mapstructure:"path"`
	CustomMetadata map[string]string `json:"custom_metadata" mapstructure:"custom_metadata"`
}
