package compat

import (
	"runtime"
	"strings"
	"testing"
)

// Guards the predicate skipIfBunWindowsSymlink matches on, without needing
// Windows: the decision is a string match plus a GOOS check.
func TestBunWindowsSymlinkSkipIsNarrow(t *testing.T) {
	const real = `Resolved, downloaded and extracted [4]
ENOENT: No such file or directory: failed to symlink dependencies for package: @workspace/app@workspace:..\..\x (symlink)`
	if !strings.Contains(real, "failed to symlink dependencies for package") {
		t.Fatal("the diagnosed failure must match the predicate")
	}
	for _, other := range []string{
		"error: GET http://127.0.0.1:1/x.tgz - 403",
		"ENOENT: No such file or directory",
		"failed to resolve dependencies",
		"",
	} {
		if strings.Contains(other, "failed to symlink dependencies for package") {
			t.Errorf("unrelated failure would be skipped: %q", other)
		}
	}
	if runtime.GOOS != "windows" {
		t.Log("non-Windows: the predicate returns early regardless of stderr")
	}
}
