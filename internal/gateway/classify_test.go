package gateway

import (
	"net/http"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name, method, path string
		kind               RequestKind
		pkg, version       string
	}{
		{"unscoped metadata", http.MethodGet, "/lodash", Metadata, "lodash", ""},
		{"encoded scoped metadata", http.MethodGet, "/@scope%2Fpkg", Metadata, "@scope/pkg", ""},
		{"scoped metadata", http.MethodHead, "/@scope/pkg", Metadata, "@scope/pkg", ""},
		{"unscoped tarball", http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", Tarball, "lodash", "4.17.21"},
		{"scoped tarball", http.MethodGet, "/@scope/pkg/-/pkg-1.2.3.tgz", Tarball, "@scope/pkg", "1.2.3"},
		{"encoded scoped tarball", http.MethodGet, "/@scope%2Fpkg/-/pkg-1.2.3.tgz", Tarball, "@scope/pkg", "1.2.3"},
		{"health", http.MethodGet, "/-/installgate/health", Health, "", ""},
		{"mutation rejected", http.MethodPut, "/lodash", Unsupported, "", ""},
		{"registry service rejected", http.MethodGet, "/-/whoami", Unsupported, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			if got.Kind != tt.kind || got.Package != tt.pkg || got.Version != tt.version {
				t.Fatalf("Classify() = %#v, want kind=%q package=%q version=%q", got, tt.kind, tt.pkg, tt.version)
			}
		})
	}
}
