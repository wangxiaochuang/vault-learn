package command

import (
	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/vault"
)

var (
	adjustCoreConfigForEnt = adjustCoreConfigForEntNoop
	checkStorageTypeForEnt = checkStorageTypeForEntNoop
)

func adjustCoreConfigForEntNoop(config *server.Config, coreConfig *vault.CoreConfig) {
}

var getFIPSInfoKey = getFIPSInfoKeyNoop

func getFIPSInfoKeyNoop() string {
	return ""
}

func checkStorageTypeForEntNoop(coreConfig *vault.CoreConfig) error {
	return nil
}
