// Package version holds build version information.
package version

// Version is the iampath version. It is overridden at release build time
// with -ldflags "-X github.com/Opsbreak/iampath/internal/version.Version=...".
var Version = "0.1.0"

// Name is the tool name.
const Name = "iampath"

// URL is the project home page.
const URL = "https://github.com/Opsbreak/iampath"
