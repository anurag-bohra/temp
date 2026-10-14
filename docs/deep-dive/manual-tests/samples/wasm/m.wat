(module
  (import "env" "send" (func $send (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "198.51.100.7")
  (func (export "beacon") (call $send (i32.const 0) (i32.const 12))))
