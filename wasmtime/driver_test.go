package wasmtime

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	pluginLoader "github.com/hashicorp/nomad/helper/pluginutils/loader"
)


func Test_Plugin_Parse(t *testing.T) {
	plugin := NewPlugin(log.NewDefault())
	plugin.
}
