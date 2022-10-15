job "wasmtime-hello-world" {
  datacenters = ["dc1"]
  type        = "service"

  group "wasmtime-hello-world" {
    task "wasmtime-hello-world" {
      driver = "nomad-driver-wasmtime"

      config {
        //module_path = "/Users/derekstrickland/code/spin/examples/wagi-http-rust/target/wasm32-wasi/debug/wagihelloworld.wasm"
        // wat_file_path = "/Users/derekstrickland/code/nomad-driver-wasmtime/example/wagi-http.wat"
        call_func  = "gcd"
        module_wat = <<EOF
        (module
          (func $gcd (param i32 i32) (result i32)
            (local i32)
            block  ;; label = @1
              block  ;; label = @2
                local.get 0
                br_if 0 (;@2;)
                local.get 1
                local.set 2
                br 1 (;@1;)
              end
              loop  ;; label = @2
                local.get 1
                local.get 0
                local.tee 2
                i32.rem_u
                local.set 0
                local.get 2
                local.set 1
                local.get 0
                br_if 0 (;@2;)
              end
            end
            local.get 2
          )
          (export "gcd" (func $gcd))
        )
        EOF
      }
    }
  }
}
