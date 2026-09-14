package gateway

import (
	"net/http"
	"net/url"
	"strings"
)

type RequestKind string

const (
	Metadata    RequestKind = "metadata"
	Tarball     RequestKind = "tarball"
	Health      RequestKind = "health"
	Ready       RequestKind = "ready"
	Unsupported RequestKind = "unsupported"
)

type Route struct {
	Kind    RequestKind
	Package string
	Version string
}

// Classify recognizes the public npm read paths InstallGate intends to proxy.
func Classify(method, escapedPath string) Route {
	if method != http.MethodGet && method != http.MethodHead {
		return Route{Kind: Unsupported}
	}
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil {
		return Route{Kind: Unsupported}
	}
	path := strings.Trim(decoded, "/")
	if path == "-/installgate/health" {
		return Route{Kind: Health}
	}
	if path == "-/installgate/ready" {
		return Route{Kind: Ready}
	}
	if path == "" || strings.HasPrefix(path, "-/") {
		return Route{Kind: Unsupported}
	}

	parts := strings.Split(path, "/")
	packageName, rest, ok := packageAndRest(parts)
	if !ok {
		return Route{Kind: Unsupported}
	}
	if len(rest) == 0 {
		return Route{Kind: Metadata, Package: packageName}
	}
	if len(rest) == 2 && rest[0] == "-" && strings.HasSuffix(rest[1], ".tgz") {
		return Route{Kind: Tarball, Package: packageName, Version: versionFromTarball(packageName, rest[1])}
	}
	return Route{Kind: Unsupported}
}

func packageAndRest(parts []string) (string, []string, bool) {
	if len(parts) == 0 || parts[0] == "" {
		return "", nil, false
	}
	if strings.HasPrefix(parts[0], "@") {
		if len(parts) == 1 && strings.Contains(parts[0], "/") {
			return parts[0], nil, true
		}
		if len(parts) < 2 || parts[1] == "" {
			return "", nil, false
		}
		return parts[0] + "/" + parts[1], parts[2:], true
	}
	return parts[0], parts[1:], true
}

func versionFromTarball(packageName, filename string) string {
	base := strings.TrimSuffix(filename, ".tgz")
	name := packageName
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	prefix := name + "-"
	return strings.TrimPrefix(base, prefix)
}
