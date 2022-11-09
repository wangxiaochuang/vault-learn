package framework

import (
	"time"
)

type Secret struct {
	Type string

	Fields map[string]*FieldSchema

	DefaultDuration time.Duration

	Renew OperationFunc

	Revoke OperationFunc
}
