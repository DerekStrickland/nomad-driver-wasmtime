job "wasmtime-hello-world" {
  datacenters = ["dc1"]
  type        = "service"

  group "wasmtime-hello-world" {
    task "wasmtime-hello-world" {
      driver = "nomad-driver-wasmtime"

      config {
        module_path = "/Users/derekstrickland/code/nomad-driver-wasmtime/example/hello-world/target/wasm32-wasi/debug/hello-world.wasm"
        call_func   = "main"
      }
    }
  }
}
