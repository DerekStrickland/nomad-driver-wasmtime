package wasmtime

import (
	"github.com/hashicorp/nomad/client/taskenv"
	"github.com/hashicorp/nomad/plugins/drivers"
)

type ModuleConfig struct {
	Name                 string
	Src                  string
	CallFunc             string
	NetworkNamespacePath string
	SecretsDirSrc        string
	TaskDirSrc           string
	AllocDirSrc          string
	SecretsDirDest       string
	TaskDirDest          string
	AllocDirDest         string
	Env                  []string
	MemoryLimit          int64
	MemoryHardLimit      int64
	CPUShares            int64
	User                 string
}

func newModuleConfig(cfg *drivers.TaskConfig) *ModuleConfig {
	networkNamespacePath := ""
	if cfg.NetworkIsolation != nil && cfg.NetworkIsolation.Path != "" {
		networkNamespacePath = cfg.NetworkIsolation.Path
	}

	return &ModuleConfig{
		Name:          cfg.Name + "-" + cfg.AllocID,
		SecretsDirSrc: cfg.TaskDir().SecretsDir,
		TaskDirSrc:    cfg.TaskDir().LocalDir,
		AllocDirSrc:   cfg.TaskDir().SharedAllocDir,

		// Setup destination paths for secrets, task and alloc directories.
		SecretsDirDest:       cfg.Env[taskenv.SecretsDir],
		TaskDirDest:          cfg.Env[taskenv.TaskLocalDir],
		AllocDirDest:         cfg.Env[taskenv.AllocDir],
		NetworkNamespacePath: networkNamespacePath,
		// memory and cpu are coming from the resources stanza of the nomad job.
		// https://www.nomadproject.io/docs/job-specification/resources
		MemoryLimit:     cfg.Resources.NomadResources.Memory.MemoryMB * 1024 * 1024,
		MemoryHardLimit: cfg.Resources.NomadResources.Memory.MemoryMaxMB * 1024 * 1024,
		CPUShares:       cfg.Resources.LinuxResources.CPUShares,
		User:            cfg.User,
	}
}
