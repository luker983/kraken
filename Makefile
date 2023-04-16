all: server

wasm:
	GOOS=js GOARCH=wasm go build -o assets/static/transfer.wasm cmd/wasm/*.go

clean_gzip:
	rm -rf compressed_assets

gzip: clean_gzip wasm
	cp -r assets compressed_assets
	gzip -r compressed_assets

server: wasm gzip
	go build -o cmd/server/server cmd/server/*.go
