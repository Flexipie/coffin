package vault

import (
	"fmt"
	"regexp"
	"strings"
)

var segmentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Windows-reserved device names, rejected as segments so a vault
// checked out on Windows stays usable (FORMAT.md, "Slugs and names").
var reservedSegments = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// NormalizeSlug lowercases name and validates every /-separated
// segment against the FORMAT.md slug rules. FORMAT.md also calls for
// NFC normalization before lowercasing, but the ASCII-only segment
// regex makes that vacuous (any non-ASCII input is rejected either
// way), so no x/text dependency is needed. Uniqueness is by
// construction: only normalized names are ever written, so a plain
// os.Stat doubles as the case-insensitive existence check.
func NormalizeSlug(name string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(name))
	if s == "" {
		return "", fmt.Errorf("coffin: empty name")
	}
	segments := strings.Split(s, "/")
	for _, seg := range segments {
		if seg == "" {
			return "", fmt.Errorf("coffin: invalid name %q: empty path segment", name)
		}
		if !segmentRe.MatchString(seg) {
			return "", fmt.Errorf("coffin: invalid name %q: segment %q must match %s", name, seg, segmentRe)
		}
		// Windows reserves the bare device name and any extension of
		// it (con, con.txt, ...), so check the part before the first
		// dot.
		base := seg
		if i := strings.IndexByte(seg, '.'); i >= 0 {
			base = seg[:i]
		}
		if reservedSegments[base] {
			return "", fmt.Errorf("coffin: invalid name %q: %q is a reserved name on Windows", name, seg)
		}
	}
	return strings.Join(segments, "/"), nil
}

// lastSegment returns the part of a normalized slug after the final
// slash; this is the human-facing "name" header field.
func lastSegment(slug string) string {
	if i := strings.LastIndexByte(slug, '/'); i >= 0 {
		return slug[i+1:]
	}
	return slug
}
