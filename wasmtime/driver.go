package wasmtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/hashicorp/consul-template/signals"
	"github.com/hashicorp/go-hclog"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/stats"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	"github.com/hashicorp/nomad/plugins/shared/structs"
)

const (
	PluginName          = "wasmtime-driver"
	PluginVersion       = "v0.0.1"
	fingerprintInterval = 30 * time.Second
	taskHandleVersion   = 1
)

var (
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     PluginVersion,
		Name:              PluginName,
	}

	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"enabled": hclspec.NewDefault(
			hclspec.NewAttr("enabled", "bool", false),
			hclspec.NewLiteral("true"),
		),
		"wasmtime_runtime": hclspec.NewDefault(
			hclspec.NewAttr("wasmtime_runtime", "string", false),
			hclspec.NewLiteral("wasmtime"), // Default assumes it's on the path
		),
		"wasmtime_version": hclspec.NewAttr("wasmtime_version", "string", true),
		"stats_interval": hclspec.NewDefault(
			hclspec.NewAttr("stats_interval", "string", false),
			hclspec.NewLiteral("30s"), // Default stats interval to 30s
		),
	})

	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"module_path": hclspec.NewAttr("module_path", "string", false),
		"module_wat":  hclspec.NewAttr("module_wat", "string", false),
		"call_func":   hclspec.NewAttr("call_func", "string", true),
		"wasmtime_config": hclspec.NewBlock("wasmtime_config", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"debug_info": hclspec.NewDefault(
				hclspec.NewAttr("debug_info", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"wasm_threads": hclspec.NewDefault(
				hclspec.NewAttr("wasm_threads", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"wasm_reference_types": hclspec.NewDefault(
				hclspec.NewAttr("wasm_reference_types", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"wasm_simd": hclspec.NewDefault(
				hclspec.NewAttr("wasm_simd", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"wasm_bulk_memory": hclspec.NewDefault(
				hclspec.NewAttr("wasm_bulk_memory", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"wasm_multi_value": hclspec.NewDefault(
				hclspec.NewAttr("wasm_multi_value", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"wasm_multi_memory": hclspec.NewDefault(
				hclspec.NewAttr("wasm_multi_memory", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"wasm_memory_64": hclspec.NewDefault(
				hclspec.NewAttr("wasm_memory_64", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"consume_fuel": hclspec.NewDefault(
				hclspec.NewAttr("consume_fuel", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"compiler": hclspec.NewDefault(
				hclspec.NewAttr("compiler", "number", false),
				hclspec.NewLiteral("1"),
				// see this for enum values https://docs.wasmtime.dev/api/wasmtime/enum.Strategy.html
			),
			"cranelift_debug_verifier": hclspec.NewDefault(
				hclspec.NewAttr("cranelift_debug_verifier", "bool", false),
				hclspec.NewLiteral("false"),
			),
			"cranelift_opt_level": hclspec.NewDefault(
				hclspec.NewAttr("cranelift_opt_level", "number", false),
				hclspec.NewLiteral("0"),
				// see this link for enum values https://docs.wasmtime.dev/api/cranelift/prelude/settings/enum.OptLevel.html
			),
			"profiler": hclspec.NewDefault(
				hclspec.NewAttr("profiler", "number", false),
				hclspec.NewLiteral("0"),
				// see this link for enum values https://docs.wasmtime.dev/api/wasmtime/enum.ProfilingStrategy.html
			),
		})),
	})

	capabilities = &drivers.Capabilities{
		SendSignals: true,
		Exec:        true,
		FSIsolation: drivers.FSIsolationImage,
		NetIsolationModes: []drivers.NetIsolationMode{
			drivers.NetIsolationModeHost,
			drivers.NetIsolationModeGroup,
			drivers.NetIsolationModeTask,
		},
		MustInitiateNetwork: false,
		MountConfigs:        drivers.MountConfigSupportAll,
		RemoteTasks:         false,
	}
)

type Config struct {
	Enabled         bool   `codec:"enabled"`
	WasmtimeRuntime string `codec:"wasmtime_runtime"`
	WasmtimeVersion string `codec:"wasmtime_version"`
	StatsInterval   string `codec:"stats_interval"`
}

type TaskConfig struct {
	ModulePath     string         `codec:"module_path"`
	ModuleWat      string         `codec:"module_wat"`
	CallFunc       string         `codec:"call_func"`
	WasmtimeConfig WasmtimeConfig `codec:"wasmtime_config`
}

func (tcfg *TaskConfig) Validate(nomadTaskConfig *drivers.TaskConfig) error {
	if tcfg.CallFunc == "" {
		return fmt.Errorf("invalid driver config: call func must be set")
	}

	if tcfg.ModulePath != "" && tcfg.ModuleWat != "" {
		return fmt.Errorf("invalid driver config: only module path or module wat can be set")
	}

	if tcfg.ModulePath == "" && tcfg.ModuleWat == "" {
		return fmt.Errorf("invalid driver config: either module path or module wat must be set")
	}

	// TODO: Read up on host networking expectations in wasmtime
	if tcfg.HostNetwork && nomadTaskConfig.NetworkIsolation != nil {
		return fmt.Errorf("host_network and bridge network mode are mutually exclusive, and only one of them should be set")
	}
}

// For full reference see https://docs.wasmtime.dev/api/wasmtime/struct.Config.html
// Note that this struct reflects the values that are configurable via wasmtime-go
// which does include the full set of possible config options at the time of this writing.
type WasmtimeConfig struct {
	DebugInfo              bool `codec:"debug_info"`
	WasmThreads            bool `codec:"wasm_threads"`
	WasmReferenceTypes     bool `codec:"wasm_reference_types"`
	WasmSIMD               bool `codec:"wasm_simd"`
	WasmBulkMemory         bool `codec:"wasm_bulk_memory"`
	WasmMultiValue         bool `codec:"wasm_multi_value"`
	WasmMultiMemory        bool `codec:"wasm_multi_memory"`
	WasmMemory64           bool `codec:"wasm_memory_64"`
	ConsumeFuel            bool `codec:"consume_fuel"`
	CompilationStrategy    int8 `codec:"compiler_strategy"`
	CraneliftDebugVerifier bool `codec:"cranelift_debug_verifier"`
	CraneliftOptLevel      int8 `codec:"cranelift_opt_level"`
	ProfilingStrategy      int8 `codec:"profiling_strategy":`
}

func (wcfg *WasmtimeConfig) toNative() *wasmtime.Config {
	result := wasmtime.NewConfig()

	result.SetDebugInfo(wcfg.DebugInfo)
	result.SetWasmThreads(wcfg.WasmThreads)
	result.SetWasmReferenceTypes(wcfg.WasmReferenceTypes)
	result.SetWasmSIMD(wcfg.WasmSIMD)
	result.SetWasmBulkMemory(wcfg.WasmBulkMemory)
	result.SetWasmMultiValue(wcfg.WasmMultiValue)
	result.SetWasmMultiMemory(wcfg.WasmMultiMemory)
	result.SetWasmMemory64(wcfg.WasmMemory64)
	result.SetConsumeFuel(wcfg.ConsumeFuel)
	result.SetStrategy(wasmtime.Strategy(wcfg.CompilationStrategy))
	result.SetCraneliftDebugVerifier(wcfg.CraneliftDebugVerifier)
	result.SetCraneliftOptLevel(wasmtime.OptLevel(wcfg.CraneliftOptLevel))
	result.SetProfiler(wasmtime.ProfilingStrategy(wcfg.ProfilingStrategy))

	return result
}

type TaskState struct {
	StartedAt      time.Time
	TaskConfig     *drivers.TaskConfig
	ReattachConfig *structs.ReattachConfig
	Pid            int
	ModuleName     string
	StdoutPath     string
	StderrPath     string
}

type WasmtimeDriverPlugin struct {
	// eventer is used to handle multiplexing of TaskEvents calls such that an
	// event can be broadcast to all callers
	eventer *eventer.Eventer

	// config is the plugin configuration set by the SetConfig RPC
	config *Config

	// nomadConfig is the client config from Nomad
	nomadConfig *base.ClientDriverConfig

	// tasks is the in memory datastore mapping taskIDs to driver handles
	tasks *taskStore

	// ctx is the context for the driver. It is passed to other subsystems to
	// coordinate shutdown
	ctx context.Context

	// ctxCancelFunc is called when the driver is shutting down and cancels
	// the ctx passed to any subsystems
	ctxCancelFunc context.CancelFunc

	// logger will log to the Nomad agent
	logger log.Logger

	// context for wasmtime
	ctxWasmtime context.Context

	// wasmtime engine
	// see this link for full documentation https://docs.wasmtime.dev/api/wasmtime/struct.Engine.html
	engine *wasmtime.Engine

	// wasmtime store
	// see this link for full documentation https://docs.wasmtime.dev/api/wasmtime/struct.Store.html
	store *wasmtime.Store

	// duration to publish stats at
	statsInterval time.Duration
}

func NewPlugin(logger log.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(PluginName)

	return &WasmtimeDriverPlugin{
		eventer:       eventer.NewEventer(ctx, logger),
		config:        &Config{},
		tasks:         newTaskStore(),
		logger:        logger,
		ctx:           ctx,
		ctxCancelFunc: cancel,
	}
}

// PluginInfo returns information describing the plugin.
func (d *WasmtimeDriverPlugin) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

// ConfigSchema returns the plugin configuration schema.
func (d *WasmtimeDriverPlugin) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

// SetConfig is called by the client to pass the configuration for the plugin.
func (d *WasmtimeDriverPlugin) SetConfig(cfg *base.Config) error {
	var config Config
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
	}

	// Save the configuration to the plugin
	d.config = &config

	// Validate plugin is enabled
	if !d.config.Enabled {
		return fmt.Errorf("%s not enabled on client", PluginName)
	}

	// Validate wasmtime is available
	wasmtimePath, err := exec.LookPath(d.config.WasmtimeRuntime)
	if err != nil {
		return fmt.Errorf("wasmtime is not available on client at %s", wasmtimePath)
	}
	d.logger.Info("wasmtime is available on client at %s\n", wasmtimePath)

	// Validate wasmtime version is set
	if d.config.WasmtimeVersion == "" {
		return errors.New("wastime_version is required")
	}

	// Save the Nomad agent configuration
	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	return nil
}

// TaskConfigSchema returns the HCL schema for the configuration of a task.
func (d *WasmtimeDriverPlugin) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

// Capabilities returns the features supported by the driver.
func (d *WasmtimeDriverPlugin) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

// Fingerprint returns a channel that will be used to send health information
// and other driver specific node attributes.
func (d *WasmtimeDriverPlugin) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

// handleFingerprint manages the channel and the flow of fingerprint data.
func (d *WasmtimeDriverPlugin) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)

	// Nomad expects the initial fingerprint to be sent immediately
	ticker := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			// after the initial fingerprint we set the fingerprint interval
			ticker.Reset(fingerprintInterval)
			ch <- d.buildFingerprint()
		}
	}
}

// buildFingerprint returns the driver's fingerprint data
func (d *WasmtimeDriverPlugin) buildFingerprint() *drivers.Fingerprint {
	fp := &drivers.Fingerprint{
		Attributes:        map[string]*structs.Attribute{},
		Health:            drivers.HealthStateHealthy,
		HealthDescription: drivers.DriverHealthy,
	}

	// Implement fingerprinting logic to populate health and driver
	// attributes.
	//
	// Fingerprinting is used by the plugin to relay two important information
	// to Nomad: health state and node attributes.
	//
	// If the plugin reports to be unhealthy, or doesn't send any fingerprint
	// data in the expected interval of time, Nomad will restart it.
	//
	// Node attributes can be used to report any relevant information about
	// the node in which the plugin is running (specific library availability,
	// installed versions of a software etc.). These attributes can then be
	// used by an operator to set job constrains.

	// Fingerprint the wasmtime version
	var outBuf, errBuf bytes.Buffer
	cmd := exec.Command(d.config.WasmtimeRuntime, "--version")
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		d.logger.Warn("failed to fingerprint wasmtime version: %v", err)
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUndetected,
			HealthDescription: "wasmtime not found",
		}
	}

	if errBuf.Len() != 0 {
		d.logger.Warn("wasmtime version check returned error: %v", string(errBuf.Bytes()))
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUnhealthy,
			HealthDescription: fmt.Sprintf("unable to fingerprint wasmtime version: %s", string(outBuf.Bytes())),
		}
	}

	// We set the wasmtime version as attributes
	re := regexp.MustCompile("[0-9]\\.[0-9]\\.[0-9]")
	version := re.FindString(string(outBuf.Bytes()))

	fp.Attributes["driver.wasmtime.version"] = structs.NewStringAttribute(version)

	return fp
}

// StartTask returns a task handle and a driver network if necessary.
func (d *WasmtimeDriverPlugin) StartTask(nomadTaskConfig *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(nomadTaskConfig.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", nomadTaskConfig.ID)
	}

	var taskConfig TaskConfig
	if err := nomadTaskConfig.DecodeDriverConfig(&taskConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %v", err)
	}

	err := taskConfig.Validate(nomadTaskConfig)
	if err != nil {
		return nil, nil, err
	}

	d.logger.Info("starting task", "driver_cfg", hclog.Fmt("%+v", taskConfig))
	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = nomadTaskConfig

	// Driver specific mechanism to start the task.
	//
	// Once the task is started you will need to store any relevant runtime
	// information in a taskHandle and TaskState. The taskHandle will be
	// stored in-memory in the plugin and will be used to interact with the
	// task.
	//
	// The TaskState will be returned to the Nomad client inside a
	// drivers.TaskHandle instance. This TaskHandle will be sent back to plugin
	// if the task ever needs to be recovered, so the TaskState should contain
	// enough information to handle that.

	d.engine = wasmtime.NewEngineWithConfig(taskConfig.WasmtimeConfig.toNative())
	d.buildStore(nomadTaskConfig)
	d.ctxWasmtime = d.store.Context()

	moduleConfig := newModuleConfig(nomadTaskConfig)

	module, err := d.createModule(&taskConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("error in creating module: %v", err)
	}

	d.logger.Info(fmt.Sprintf("successfully created module with name: %s\n", moduleConfig.Name))

	instance, err := wasmtime.NewInstance(d.store, module, []wasmtime.AsExtern{})
	if err != nil {
		return nil, nil, fmt.Errorf("error in creating module instance: %v", err)
	}

	callFunc := instance.GetExport(d.store, moduleConfig.CallFunc).Func()
	if callFunc == nil {
		return nil, nil, fmt.Errorf("unable to export call func: %s", moduleConfig.CallFunc)
	}

	val, err := callFunc.Call(d.store)
	if err != nil {
		return nil, nil, fmt.Errorf("error invoking call func: %s", moduleConfig.CallFunc)
	}

	task, err := d.createTask(container, nomadTaskConfig.StdoutPath, nomadTaskConfig.StderrPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error in creating task: %v", err)
	}

	d.logger.Info(fmt.Sprintf("successfully created task with ID: %s\n", task.ID()))

	h := &taskHandle{
		taskConfig:     nomadTaskConfig,
		procState:      drivers.TaskStateRunning,
		startedAt:      time.Now().Round(time.Millisecond),
		logger:         d.logger,
		totalCpuStats:  stats.NewCpuStats(),
		userCpuStats:   stats.NewCpuStats(),
		systemCpuStats: stats.NewCpuStats(),
		module:         module,
		moduleName:     moduleConfig.Name,
		task:           task,
	}

	driverState := TaskState{
		StartedAt:     h.startedAt,
		ContainerName: containerName,
		StdoutPath:    cfg.StdoutPath,
		StderrPath:    cfg.StderrPath,
	}

	if err := handle.SetDriverState(&driverState); err != nil {
		return nil, nil, fmt.Errorf("failed to set driver state: %v", err)
	}

	d.tasks.Set(cfg.ID, h)

	go h.run(d.ctxContainerd)
	return handle, nil, nil
}

func (d *WasmtimeDriverPlugin) buildStore(cfg *drivers.TaskConfig) {
	store := wasmtime.NewStore(d.engine)

	if len(cfg.Env) != 0 {
		keys := []string{"WASMTIME"}
		vals := []string{"GO"}
		for key, val := range cfg.Env {
			keys = append(keys, key)
			vals = append(vals, val)
		}
		wasiConfig := wasmtime.NewWasiConfig()
		wasiConfig.SetEnv(keys, vals)
		store.SetWasi(wasiConfig)
	}

	d.store = store
}

func (d *WasmtimeDriverPlugin) createModule(taskConfig *TaskConfig) (*wasmtime.Module, error) {
	if taskConfig.ModuleWat != "" {
		wasm, err := wasmtime.Wat2Wasm(taskConfig.ModuleWat)
		if err != nil {
			return nil, fmt.Errorf("error converting wat to wasm: %v", err)
		}

		return wasmtime.NewModule(d.engine, wasm)
	}

	return wasmtime.NewModuleFromFile(d.engine, taskConfig.ModulePath)
}

// RecoverTask recreates the in-memory state of a task from a TaskHandle.
func (d *WasmtimeDriverPlugin) RecoverTask(handle *drivers.TaskHandle) error {
	if handle == nil {
		return errors.New("error: handle cannot be nil")
	}

	if _, ok := d.tasks.Get(handle.Config.ID); ok {
		return nil
	}

	var taskState TaskState
	if err := handle.GetDriverState(&taskState); err != nil {
		return fmt.Errorf("failed to decode task state from handle: %v", err)
	}

	var driverConfig TaskConfig
	if err := taskState.TaskConfig.DecodeDriverConfig(&driverConfig); err != nil {
		return fmt.Errorf("failed to decode driver config: %v", err)
	}

	// TODO: implement driver specific logic to recover a task.
	//
	// Recovering a task involves recreating and storing a taskHandle as if the
	// task was just started.
	//
	// In the example below we use the executor to re-attach to the process
	// that was created when the task first started.
	plugRC, err := structs.ReattachConfigToGoPlugin(taskState.ReattachConfig)
	if err != nil {
		return fmt.Errorf("failed to build ReattachConfig from taskConfig state: %v", err)
	}

	execImpl, pluginClient, err := executor.ReattachToExecutor(plugRC, d.logger)
	if err != nil {
		return fmt.Errorf("failed to reattach to executor: %v", err)
	}

	h := &taskHandle{
		exec:         execImpl,
		pid:          taskState.Pid,
		pluginClient: pluginClient,
		taskConfig:   taskState.TaskConfig,
		procState:    drivers.TaskStateRunning,
		startedAt:    taskState.StartedAt,
		exitResult:   &drivers.ExitResult{},
	}

	d.tasks.Set(taskState.TaskConfig.ID, h)

	go h.run()
	return nil
}

// WaitTask returns a channel used to notify Nomad when a task exits.
func (d *WasmtimeDriverPlugin) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.ExitResult)
	go d.handleWait(ctx, handle, ch)
	return ch, nil
}

func (d *WasmtimeDriverPlugin) handleWait(ctx context.Context, handle *taskHandle, ch chan *drivers.ExitResult) {
	defer close(ch)
	var result *drivers.ExitResult

	// TODO: implement driver specific logic to notify Nomad the task has been
	// completed and what was the exit result.
	//
	// When a result is sent in the result channel Nomad will stop the task and
	// emit an event that an operator can use to get an insight on why the task
	// stopped.
	//
	// In the example below we block and wait until the executor finishes
	// running, at which point we send the exit code and signal in the result
	// channel.
	ps, err := handle.exec.Wait(ctx)
	if err != nil {
		result = &drivers.ExitResult{
			Err: fmt.Errorf("executor: error waiting on process: %v", err),
		}
	} else {
		result = &drivers.ExitResult{
			ExitCode: ps.ExitCode,
			Signal:   ps.Signal,
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case ch <- result:
		}
	}
}

// StopTask stops a running task with the given signal and within the timeout window.
func (d *WasmtimeDriverPlugin) StopTask(taskID string, timeout time.Duration, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	// TODO: implement driver specific logic to stop a task.
	//
	// The StopTask function is expected to stop a running task by sending the
	// given signal to it. If the task does not stop during the given timeout,
	// the driver must forcefully kill the task.
	//
	// In the example below we let the executor handle the task shutdown
	// process for us, but you might need to customize this for your own
	// implementation.
	if err := handle.exec.Shutdown(signal, timeout); err != nil {
		if handle.pluginClient.Exited() {
			return nil
		}
		return fmt.Errorf("executor Shutdown failed: %v", err)
	}

	return nil
}

// DestroyTask cleans up and removes a task that has terminated.
func (d *WasmtimeDriverPlugin) DestroyTask(taskID string, force bool) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if handle.IsRunning() && !force {
		return errors.New("cannot destroy running task")
	}

	// TODO: implement driver specific logic to destroy a complete task.
	//
	// Destroying a task includes removing any resources used by task and any
	// local references in the plugin. If force is set to true the task should
	// be destroyed even if it's currently running.
	//
	// In the example below we use the executor to force shutdown the task
	// (timeout equals 0).
	if !handle.pluginClient.Exited() {
		if err := handle.exec.Shutdown("", 0); err != nil {
			handle.logger.Error("destroying executor failed", "err", err)
		}

		handle.pluginClient.Kill()
	}

	d.tasks.Delete(taskID)
	return nil
}

// InspectTask returns detailed status information for the referenced taskID.
func (d *WasmtimeDriverPlugin) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	return handle.TaskStatus(), nil
}

// TaskStats returns a channel which the driver should send stats to at the given interval.
func (d *WasmtimeDriverPlugin) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	// TODO: implement driver specific logic to send task stats.
	//
	// This function returns a channel that Nomad will use to listen for task
	// stats (e.g., CPU and memory usage) in a given interval. It should send
	// stats until the context is canceled or the task stops running.
	//
	// In the example below we use the Stats function provided by the executor,
	// but you can build a set of functions similar to the fingerprint process.
	return handle.exec.Stats(ctx, interval)
}

// TaskEvents returns a channel that the plugin can use to emit task related events.
func (d *WasmtimeDriverPlugin) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

// SignalTask forwards a signal to a task.
// This is an optional capability.
func (d *WasmtimeDriverPlugin) SignalTask(taskID string, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	// TODO: implement driver specific signal handling logic.
	//
	// The given signal must be forwarded to the target taskID. If this plugin
	// doesn't support receiving signals (capability SendSignals is set to
	// false) you can just return nil.
	sig := os.Interrupt
	if s, ok := signals.SignalLookup[signal]; ok {
		sig = s
	} else {
		d.logger.Warn("unknown signal to send to task, using SIGINT instead", "signal", signal, "task_id", handle.taskConfig.ID)

	}
	return handle.exec.Signal(sig)
}

// ExecTask returns the result of executing the given command inside a task.
// This is an optional capability.
func (d *WasmtimeDriverPlugin) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	// TODO: implement driver specific logic to execute commands in a task.
	return nil, errors.New("This driver does not support exec")
}
