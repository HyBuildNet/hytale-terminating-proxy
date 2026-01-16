module quic-terminator

go 1.25.0

require (
	github.com/klauspost/compress v1.18.2
	github.com/quic-go/quic-go v0.57.1
	protohytale v0.0.0
)

require (
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace protohytale => ../protohytale
