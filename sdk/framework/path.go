package framework

import (
	"github.com/hashicorp/vault/sdk/helper/license"
	"github.com/hashicorp/vault/sdk/logical"
)

// p50
type Path struct {
	Pattern string

	Fields map[string]*FieldSchema

	Operations map[logical.Operation]OperationHandler

	Callbacks map[logical.Operation]OperationFunc

	ExistenceCheck ExistenceFunc

	FeatureRequired license.Features

	Deprecated bool

	HelpSynopsis    string
	HelpDescription string

	DisplayAttrs *DisplayAttributes

	TakesArbitraryInput bool
}

type OperationHandler interface {
	Handler() OperationFunc
	Properties() OperationProperties
}

// p136
type OperationProperties struct {
	Summary string

	Description string

	Examples []RequestExample

	Responses map[int][]Response

	Unpublished bool

	Deprecated bool

	ForwardPerformanceStandby bool

	ForwardPerformanceSecondary bool

	DisplayAttrs *DisplayAttributes
}

// p191
type DisplayAttributes struct {
	Name string `json:"name,omitempty"`

	Value interface{} `json:"value,omitempty"`

	Sensitive bool `json:"sensitive,omitempty"`

	Navigation bool `json:"navigation,omitempty"`

	ItemType string `json:"itemType,omitempty"`

	Group string `json:"group,omitempty"`

	Action string `json:"action,omitempty"`

	EditType string `json:"editType,omitempty"`
}

// p221
type RequestExample struct {
	Description string                 // optional description of the request
	Data        map[string]interface{} // map version of sample JSON request data

	// Optional example response to the sample request. This approach is considered
	// provisional for now, and this field may be changed or removed.
	Response *Response
}

type Response struct {
	Description string            // summary of the the response and should always be provided
	MediaType   string            // media type of the response, defaulting to "application/json" if empty
	Example     *logical.Response // example response data
}
