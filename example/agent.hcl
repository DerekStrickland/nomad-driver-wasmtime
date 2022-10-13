log_level = "TRACE"

plugin "nomad-driver-wasmtime" {
  config {
    enabled          = true
    wasmtime_runtime = "wasmtime"
    wasmtime_version = "1.0.1"
    stats_interval   = "15s"
  }
}
