package main

import (
	"syscall/js"
)

func main() {
	wasmBlockingChan := make(chan struct{})
	// js.Global().Set("signString", js.FuncOf(SignString))
	js.Global().Set("registerFunc", js.FuncOf(RegisterFunc))
	js.Global().Set("loginFunc", js.FuncOf(LoginFunc))
	<-wasmBlockingChan
}