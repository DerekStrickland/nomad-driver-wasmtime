package wasmtime

import (
	"errors"
	"fmt"
	"os"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/hashicorp/nomad/client/taskenv"
	"github.com/hashicorp/nomad/plugins/drivers"
)

type Runtime struct {
	linker   *wasmtime.Linker
	store    *wasmtime.Store
	module   *wasmtime.Module
	instance *wasmtime.Instance
	config   *RuntimeConfig
}

func NewRuntime(cfg *RuntimeConfig) (*Runtime, error) {
	engine := wasmtime.NewEngineWithConfig(cfg.TaskConfig.WasmtimeConfig.toNative())
	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		return nil, fmt.Errorf("error linking WASI: %s", err)
	}

	keys, vals := getEnvars(cfg.NomadTaskConfig)

	wasiConfig := wasmtime.NewWasiConfig()
	wasiConfig.SetEnv(keys, vals)

	if cfg.TaskConfig.InheritStdErr {
		wasiConfig.InheritStderr()
	} else {
		wasiConfig.SetStderrFile(cfg.NomadTaskConfig.StderrPath)
	}

	if cfg.TaskConfig.InheritStdOut {
		wasiConfig.InheritStdout()
	} else {
		wasiConfig.SetStdoutFile(cfg.NomadTaskConfig.StdoutPath)
	}

	// TODO: Think about Nomad expectations around stdin and exec.
	wasiConfig.InheritStdin()
	// Set the local dir for the module to have isolated filesystem access
	wasiConfig.PreopenDir(cfg.TaskDirDest(), ".")

	store.SetWasi(wasiConfig)

	runtime := &Runtime{
		store:  store,
		linker: linker,
		config: cfg,
	}

	module, err := runtime.createModule()
	if err != nil {
		return nil, fmt.Errorf("error creating module: %v", err)
	}

	instance, err := linker.Instantiate(store, module)
	if err != nil {
		return nil, fmt.Errorf("error creating module instance: %v", err)
	}

	runtime.module = module
	runtime.instance = instance

	// TODO: Figure out a cancellation context
	// d.ctxWasmtime = d.store.Context()

	return runtime, nil
}

func getEnvars(nomadTaskConfig *drivers.TaskConfig) ([]string, []string) {
	keys := []string{"WASMTIME"}
	vals := []string{"GO"}
	for key, val := range nomadTaskConfig.Env {
		keys = append(keys, key)
		vals = append(vals, val)
	}
	return keys, vals
}

func (r *Runtime) createModule() (*wasmtime.Module, error) {
	if r.store == nil {
		return nil, errors.New("error creating module: store not initialized")
	}

	if r.config == nil {
		return nil, errors.New("error creating module: runtime config not initialized")
	}

	if r.config.TaskConfig == nil {
		return nil, errors.New("error creating module: task config not initialized")
	}

	// TODO: Refactor to better support WatFilePath now that it's been added
	if r.config.TaskConfig.WatFilePath != "" {
		watBytes, err := os.ReadFile(r.config.TaskConfig.WatFilePath)
		wasm, err := wasmtime.Wat2Wasm(string(watBytes))
		if err != nil {
			return nil, fmt.Errorf("error converting wat file to wasm: %v", err)
		}

		err = wasmtime.ModuleValidate(r.store.Engine, wasm)
		if err != nil {
			return nil, fmt.Errorf("error validating wat file Wat2Wasm output: %v", err)
		}

		return wasmtime.NewModule(r.store.Engine, wasm)
	}

	if r.config.TaskConfig.ModuleWat != "" {
		wasm, err := wasmtime.Wat2Wasm(r.config.TaskConfig.ModuleWat)
		if err != nil {
			return nil, fmt.Errorf("error converting wat to wasm: %v", err)
		}

		err = wasmtime.ModuleValidate(r.store.Engine, wasm)
		if err != nil {
			return nil, fmt.Errorf("error validating Wat2Wasm output: %v", err)
		}

		return wasmtime.NewModule(r.store.Engine, wasm)
	}

	return wasmtime.NewModuleFromFile(r.store.Engine, r.config.TaskConfig.ModulePath)
}

type RuntimeConfig struct {
	NomadTaskConfig *drivers.TaskConfig
	TaskConfig      *TaskConfig
	Wat             string
	Env             []string
}

func NewRuntimeConfig(nomadTaskConfig *drivers.TaskConfig, taskConfig *TaskConfig) *RuntimeConfig {
	return &RuntimeConfig{
		NomadTaskConfig: nomadTaskConfig,
		TaskConfig:      taskConfig,
	}
}

func (c *RuntimeConfig) Name() string {
	return c.NomadTaskConfig.Name + "-" + c.NomadTaskConfig.AllocID
}

func (c *RuntimeConfig) SecretsDirSrc() string {
	return c.NomadTaskConfig.TaskDir().SecretsDir
}

func (c *RuntimeConfig) TaskDirSrc() string {
	return c.NomadTaskConfig.TaskDir().LocalDir
}

func (c *RuntimeConfig) AllocDirSrc() string {
	return c.NomadTaskConfig.TaskDir().SharedAllocDir
}

// Destination paths for secrets, task and alloc directories.
func (c *RuntimeConfig) SecretsDirDest() string {
	return c.NomadTaskConfig.Env[taskenv.SecretsDir]
}

func (c *RuntimeConfig) TaskDirDest() string {
	return c.NomadTaskConfig.Env[taskenv.TaskLocalDir]
}

func (c *RuntimeConfig) AllocDirDest() string {
	return c.NomadTaskConfig.Env[taskenv.AllocDir]
}

func (c *RuntimeConfig) NetworkNamespacePath() string {
	if c.NomadTaskConfig.NetworkIsolation != nil && c.NomadTaskConfig.NetworkIsolation.Path != "" {
		return c.NomadTaskConfig.NetworkIsolation.Path
	}

	return ""
}

// memory and cpu are coming from the resources stanza of the nomad job.
// https://www.nomadproject.io/docs/job-specification/resources
func (c *RuntimeConfig) MemoryLimit() int64 {
	return c.NomadTaskConfig.Resources.NomadResources.Memory.MemoryMB * 1024 * 1024
}

func (c *RuntimeConfig) MemoryHardLimit() int64 {
	return c.NomadTaskConfig.Resources.NomadResources.Memory.MemoryMaxMB * 1024 * 1024
}

func (c *RuntimeConfig) CPUShares() int64 {
	return c.NomadTaskConfig.Resources.LinuxResources.CPUShares
}

func (c *RuntimeConfig) User() string {
	return c.NomadTaskConfig.User
}
