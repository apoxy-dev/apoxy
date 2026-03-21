package build

import (
	"fmt"
	"strings"
)

var (
	devBuildVersion = "0.0.0-dev"
	BuildVersion    = "0.0.0-dev"
	BuildDate       = "n/a"
	CommitHash      = "n/a"
)

// IsDev returns true if the build is a development build.
func IsDev() bool {
	return strings.HasSuffix(BuildVersion, "-dev")
}

// Version returns the version string in the format of "vX.Y.Z (<commit>), built <date>".
func Version() string {
	if BuildVersion == devBuildVersion {
		return BuildVersion
	}
	return fmt.Sprintf("%s (%s), built %s", BuildVersion, CommitHash, BuildDate)
}

// UserAgent returns the user agent string for the CLI.
func UserAgent() string {
	if BuildVersion == "dev" {
		return fmt.Sprintf("apoxy-cli/%s", BuildVersion)
	}
	return fmt.Sprintf("apoxy-cli/v%s-%s (%s)", BuildVersion, CommitHash, BuildDate)
}

// APIServerUserAgent returns the user agent string for the apiserver.
func APIServerUserAgent() string {
	return fmt.Sprintf("apoxy-apiserver/%s", BuildVersion)
}
