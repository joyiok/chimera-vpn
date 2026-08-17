module chimera

go 1.25.0

require golang.org/x/sys v0.47.0

require golang.org/x/crypto v0.55.0

require (
	golang.org/x/mobile v0.0.0-20260816165457-f98cc9b3c733 // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
