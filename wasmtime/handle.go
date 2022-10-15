package wasmtime

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/nomad/client/stats"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/drivers"
)

// taskHandle should store all relevant runtime information
// such as process ID if this is a local task or other meta
// data if this driver deals with external APIs
type taskHandle struct {
	// stateLock syncs access to all fields below
	stateLock sync.RWMutex

	logger         hclog.Logger
	exec           executor.Executor
	pluginClient   *plugin.Client
	taskConfig     *drivers.TaskConfig
	procState      drivers.TaskState
	startedAt      time.Time
	completedAt    time.Time
	exitResult     *drivers.ExitResult
	totalCpuStats  *stats.CpuStats
	userCpuStats   *stats.CpuStats
	systemCpuStats *stats.CpuStats
	store          *wasmtime.Store
	module         *wasmtime.Module
	instance       *wasmtime.Instance
	moduleConfig   *ModuleConfig
	pid            int
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	return &drivers.TaskStatus{
		ID:          h.taskConfig.ID,
		Name:        h.taskConfig.Name,
		State:       h.procState,
		StartedAt:   h.startedAt,
		CompletedAt: h.completedAt,
		ExitResult:  h.exitResult,
		DriverAttributes: map[string]string{
			"pid": strconv.Itoa(h.pid),
		},
	}
}

func (h *taskHandle) IsRunning() bool {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.procState == drivers.TaskStateRunning
}

func (h *taskHandle) run(ctxWasmtime context.Context) {
	h.stateLock.Lock()
	if h.exitResult == nil {
		h.exitResult = &drivers.ExitResult{}
	}
	h.stateLock.Unlock()

	callFunc := h.instance.GetFunc(h.store, h.moduleConfig.TaskConfig.CallFunc)
	if callFunc == nil {
		h.logger.Error(fmt.Sprintf("unable to export call func: %s", h.moduleConfig.TaskConfig.CallFunc))
		return
	}

	val, err := callFunc.Call(h.store, 6, 27)
	if err != nil {
		h.logger.Error(fmt.Sprintf("error invoking call func: %s", h.moduleConfig.TaskConfig.CallFunc))
		return
	}

	h.logger.Info("ran call func", "func_name", h.moduleConfig.TaskConfig.CallFunc, "result", val.(int32))

	// TODO: wait for your task to complete and upate its state.
	ps, err := h.exec.Wait(context.Background())
	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	if err != nil {
		h.exitResult.Err = err
		h.procState = drivers.TaskStateUnknown
		h.completedAt = time.Now()
		return
	}
	h.procState = drivers.TaskStateExited
	h.exitResult.ExitCode = ps.ExitCode
	h.exitResult.Signal = ps.Signal
	h.completedAt = ps.Time
}
