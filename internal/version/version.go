// Package version carries the botjim version. Overridden at release-build
// time via -ldflags; the fallback marks a development build.
package version

// Version is the current botjim version.
const Version = "0.5.0"

// Repo is the GitHub repository self-update pulls from.
const Repo = "ziozzang/botjim"
