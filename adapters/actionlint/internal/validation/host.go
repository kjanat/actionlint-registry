package validation

import (
	"runtime/debug"

	"golang.org/x/mod/module"
)

const hostModule = "actionlint.kjanat.dev/v2"

var HostCommit = hostRevision()

func hostRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dependency := range info.Deps {
		if dependency.Path != hostModule {
			continue
		}
		if dependency.Replace != nil {
			dependency = dependency.Replace
		}
		revision, err := module.PseudoVersionRev(dependency.Version)
		if err != nil {
			return ""
		}
		return revision
	}
	return ""
}
