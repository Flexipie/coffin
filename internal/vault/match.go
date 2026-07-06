package vault

import (
	"sort"
	"strings"
)

// Match tiers, best to worst. Only entries in the best non-zero tier
// are returned, so an exact match shadows every fuzzier one.
const (
	scoreExact       = 400
	scoreLastSegment = 350
	scorePrefix      = 300
	scoreSubstring   = 200
	scoreSubsequence = 100
)

// Match scores query against every entry's Name and Path and returns
// the entries in the best-scoring tier, ordered by shorter name then
// lexicographic path. An empty result means no match; more than one
// result means the query is ambiguous.
func Match(query string, entries []EntryRef) []EntryRef {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	best := 0
	scores := make([]int, len(entries))
	for i, e := range entries {
		s := scoreCandidate(q, e.Name)
		if ps := scoreCandidate(q, e.Path); ps > s {
			s = ps
		}
		scores[i] = s
		if s > best {
			best = s
		}
	}
	if best == 0 {
		return nil
	}
	var out []EntryRef
	for i, s := range scores {
		if s == best {
			out = append(out, entries[i])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Name) != len(out[j].Name) {
			return len(out[i].Name) < len(out[j].Name)
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func scoreCandidate(q, cand string) int {
	switch {
	case q == cand:
		return scoreExact
	case q == cand[strings.LastIndexByte(cand, '/')+1:]:
		return scoreLastSegment
	case strings.HasPrefix(cand, q):
		return scorePrefix
	case strings.Contains(cand, q):
		return scoreSubstring
	case isSubsequence(q, cand):
		return scoreSubsequence
	}
	return 0
}

// isSubsequence reports whether every byte of q appears in cand in
// order (the classic fuzzy-finder match).
func isSubsequence(q, cand string) bool {
	j := 0
	for i := 0; i < len(cand) && j < len(q); i++ {
		if cand[i] == q[j] {
			j++
		}
	}
	return j == len(q)
}
