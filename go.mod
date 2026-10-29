module github.com/ddzhan19/certbumblebee

go 1.26.0

require (
	github.com/jchv/go-webview2 v0.0.0-20260205173254-56598839c808
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	software.sslmate.com/src/go-pkcs12 v0.7.4
)

require (
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/jchv/go-webview2 => ./third_party/go-webview2
