client: cmd/client.go
	go run $<

server: cmd/server.go
	go run $<

copy_assets:
	$ cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ./assets

update_wasm:
	GOOS=js GOARCH=wasm go build --o assets/main.wasm cmd/wasm/*

