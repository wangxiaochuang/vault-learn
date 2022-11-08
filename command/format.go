package command

import (
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/cli"
)

type Formatter interface {
	Output(ui cli.Ui, secret *api.Secret, data interface{}) error
	Format(data interface{}) ([]byte, error)
}

var Formatters = map[string]Formatter{
	// "json":  JsonFormatter{},
	"table": TableFormatter{},
}

func Format(ui cli.Ui) string {
	switch ui := ui.(type) {
	case *VaultUI:
		return ui.format
	}

	format := os.Getenv(EnvVaultFormat)
	if format == "" {
		format = "table"
	}

	return format
}

// p276
type TableFormatter struct{}

func (t TableFormatter) Format(data interface{}) ([]byte, error) {
	return nil, nil
}

func (t TableFormatter) Output(ui cli.Ui, secret *api.Secret, data interface{}) error {
	panic("output")
}
