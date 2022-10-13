package main

import (
	// TODO: update the path below to match your own repository
	"github.com/DerekStrickland/nomad-driver-wasmtime/wasmtime"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"
)

func main() {
	// Serve the plugin
	plugins.Serve(factory)
}

// factory returns a new instance of a nomad driver plugin
func factory(log hclog.Logger) interface{} {
	return wasmtime.NewPlugin(log)
}
