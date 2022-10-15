package wasmtime

import (
	"github.com/hashicorp/nomad/client/taskenv"
	"github.com/hashicorp/nomad/plugins/drivers"
)

type ModuleConfig struct {
	TaskConfig           *TaskConfig
	Name                 string
	Src                  string
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

func newModuleConfig(nomadTaskConfig *drivers.TaskConfig, taskConfig *TaskConfig) *ModuleConfig {
	networkNamespacePath := ""
	if nomadTaskConfig.NetworkIsolation != nil && nomadTaskConfig.NetworkIsolation.Path != "" {
		networkNamespacePath = nomadTaskConfig.NetworkIsolation.Path
	}

	return &ModuleConfig{
		TaskConfig:    taskConfig,
		Name:          nomadTaskConfig.Name + "-" + nomadTaskConfig.AllocID,
		SecretsDirSrc: nomadTaskConfig.TaskDir().SecretsDir,
		TaskDirSrc:    nomadTaskConfig.TaskDir().LocalDir,
		AllocDirSrc:   nomadTaskConfig.TaskDir().SharedAllocDir,

		// Setup destination paths for secrets, task and alloc directories.
		SecretsDirDest:       nomadTaskConfig.Env[taskenv.SecretsDir],
		TaskDirDest:          nomadTaskConfig.Env[taskenv.TaskLocalDir],
		AllocDirDest:         nomadTaskConfig.Env[taskenv.AllocDir],
		NetworkNamespacePath: networkNamespacePath,
		// memory and cpu are coming from the resources stanza of the nomad job.
		// https://www.nomadproject.io/docs/job-specification/resources
		MemoryLimit:     nomadTaskConfig.Resources.NomadResources.Memory.MemoryMB * 1024 * 1024,
		MemoryHardLimit: nomadTaskConfig.Resources.NomadResources.Memory.MemoryMaxMB * 1024 * 1024,
		CPUShares:       nomadTaskConfig.Resources.LinuxResources.CPUShares,
		User:            nomadTaskConfig.User,
	}
}
