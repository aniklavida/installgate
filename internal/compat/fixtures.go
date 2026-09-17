package compat

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// FixturePackage defines metadata and files for a test package.
type FixturePackage struct {
	Name                 string
	Version              string
	Description          string
	Dependencies         map[string]string
	PeerDependencies     map[string]string
	OptionalDependencies map[string]string
	Files                map[string]string
	TarballBytes         []byte
	IntegritySHA512      string
	ShasumSHA1           string
}

// BuildFixturePackage compiles in-memory files into a valid npm gzip-compressed tarball
// and calculates authentic SHA-512 and SHA-1 integrity digests.
func BuildFixturePackage(name, version, desc string, deps, peerDeps, optDeps map[string]string, extraFiles map[string]string) (*FixturePackage, error) {
	pkg := &FixturePackage{
		Name:                 name,
		Version:              version,
		Description:          desc,
		Dependencies:         deps,
		PeerDependencies:     peerDeps,
		OptionalDependencies: optDeps,
		Files:                make(map[string]string),
	}

	// 1. Construct package.json
	var depBlocks []string
	if len(deps) > 0 {
		depBlocks = append(depBlocks, formatJSONMap("dependencies", deps))
	}
	if len(peerDeps) > 0 {
		depBlocks = append(depBlocks, formatJSONMap("peerDependencies", peerDeps))
	}
	if len(optDeps) > 0 {
		depBlocks = append(depBlocks, formatJSONMap("optionalDependencies", optDeps))
	}

	depJSON := ""
	if len(depBlocks) > 0 {
		depJSON = ",\n  " + strings.Join(depBlocks, ",\n  ")
	}

	pkgJSON := fmt.Sprintf(`{
  "name": %q,
  "version": %q,
  "description": %q,
  "main": "index.js"%s
}
`, name, version, desc, depJSON)

	pkg.Files["package/package.json"] = pkgJSON

	// 2. Default index.js
	pkg.Files["package/index.js"] = fmt.Sprintf("module.exports = { name: %q, version: %q };\n", name, version)

	// 3. Add extra files if specified
	for fName, fContent := range extraFiles {
		normalizedPath := fName
		if !strings.HasPrefix(normalizedPath, "package/") {
			normalizedPath = "package/" + strings.TrimPrefix(normalizedPath, "/")
		}
		pkg.Files[normalizedPath] = fContent
	}

	// 4. Create gzip-compressed tar archive
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for pName, content := range pkg.Files {
		data := []byte(content)
		hdr := &tar.Header{
			Name:    pName,
			Mode:    0o644,
			Size:    int64(len(data)),
			ModTime: time.Unix(1700000000, 0).UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("failed writing tar header for %s: %w", pName, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("failed writing tar body for %s: %w", pName, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed closing tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("failed closing gzip writer: %w", err)
	}

	pkg.TarballBytes = buf.Bytes()

	// 5. Calculate digests
	h512 := sha512.Sum512(pkg.TarballBytes)
	pkg.IntegritySHA512 = "sha512-" + base64.StdEncoding.EncodeToString(h512[:])

	h1 := sha1.Sum(pkg.TarballBytes)
	pkg.ShasumSHA1 = hex.EncodeToString(h1[:])

	return pkg, nil
}

func formatJSONMap(field string, m map[string]string) string {
	var entries []string
	for k, v := range m {
		entries = append(entries, fmt.Sprintf("    %q: %q", k, v))
	}
	return fmt.Sprintf("%q: {\n%s\n  }", field, strings.Join(entries, ",\n"))
}

// DefaultFixtureRegistry builds standard test packages covering:
// - standard unscoped package
// - scoped package
// - peer dependencies
// - optional dependencies
// - tampered/corruptible test package
func DefaultFixtureRegistry() (map[string]*FixturePackage, error) {
	pkgs := make(map[string]*FixturePackage)

	// 1. Unscoped base package
	unscoped, err := BuildFixturePackage(
		"fixture-unscoped",
		"1.0.0",
		"Standard unscoped test package for InstallGate compatibility",
		nil, nil, nil, nil,
	)
	if err != nil {
		return nil, err
	}
	pkgs["fixture-unscoped"] = unscoped

	// 2. Scoped package
	scoped, err := BuildFixturePackage(
		"@testscope/fixture-scoped",
		"1.0.0",
		"Scoped test package for InstallGate compatibility",
		nil, nil, nil, nil,
	)
	if err != nil {
		return nil, err
	}
	pkgs["@testscope/fixture-scoped"] = scoped

	// 3. Peer dependency package
	peer, err := BuildFixturePackage(
		"fixture-peer",
		"1.0.0",
		"Peer dependency test package for InstallGate compatibility",
		nil,
		map[string]string{"fixture-unscoped": "^1.0.0"},
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	pkgs["fixture-peer"] = peer

	// 4. Optional dependency package
	optional, err := BuildFixturePackage(
		"fixture-optional",
		"1.0.0",
		"Optional dependency test package for InstallGate compatibility",
		nil,
		nil,
		map[string]string{"fixture-unscoped": "^1.0.0"},
		nil,
	)
	if err != nil {
		return nil, err
	}
	pkgs["fixture-optional"] = optional

	// 5. Tampered package used for corrupted-tarball detection proof
	tampered, err := BuildFixturePackage(
		"fixture-tampered",
		"1.0.0",
		"Integrity tampering target test package for InstallGate compatibility",
		nil, nil, nil, nil,
	)
	if err != nil {
		return nil, err
	}
	pkgs["fixture-tampered"] = tampered

	return pkgs, nil
}
