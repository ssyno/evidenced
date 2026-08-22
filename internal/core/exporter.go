package core

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssyno/evidenced/bundle"
	"github.com/ssyno/evidenced/evidence"
	"github.com/ssyno/evidenced/mapping"
)

// Exporter produces auditor-ready bundles: the machine-readable evidence
// set, a human-readable report, and a checksummed (and, with a key,
// signed) manifest covering both.
type Exporter struct {
	Store   Store
	Mapping *mapping.Mapping
	Key     ed25519.PrivateKey // optional; nil means checksum-only
	Clock   func() time.Time   // defaults to time.Now
}

func (e *Exporter) now() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

// Export verifies the chain, then writes a bundle directory named by
// timestamp under dir and returns its path. It refuses to export a store
// that fails verification.
func (e *Exporter) Export(dir string) (string, error) {
	records, err := e.Store.All()
	if err != nil {
		return "", fmt.Errorf("load records: %w", err)
	}
	if err := evidence.Verify(records); err != nil {
		return "", fmt.Errorf("refusing to export: %w", err)
	}
	now := e.now()
	bundleDir := filepath.Join(dir, now.UTC().Format("evidence-20060102-150405Z"))
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	files := map[string][]byte{}

	header := bundle.Header{
		Tool:        "evidenced",
		Framework:   e.frameworkName(),
		GeneratedAt: now,
		RecordCount: len(records),
		Records:     records,
	}
	machineJSON, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode evidence.json: %w", err)
	}
	files["evidence.json"] = machineJSON
	files["report.md"] = e.renderReport(records, now)

	man, err := bundle.BuildManifest(files, e.Key, now)
	if err != nil {
		return "", err
	}
	manifestJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	files["manifest.json"] = manifestJSON

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(bundleDir, name), content, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}
	return bundleDir, nil
}

func (e *Exporter) frameworkName() string {
	if e.Mapping == nil {
		return ""
	}
	return e.Mapping.Framework
}

// renderReport produces the auditor-facing Markdown report: evidence
// grouped per control, with collection failures called out.
func (e *Exporter) renderReport(records []evidence.Record, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Compliance evidence report\n\n")
	fmt.Fprintf(&b, "- Generated: %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Framework: %s\n", e.frameworkName())
	fmt.Fprintf(&b, "- Evidence records: %d\n\n", len(records))

	byControl := map[string][]evidence.Record{}
	var failures []evidence.Record
	unmapped := 0
	for _, r := range records {
		if r.Outcome == evidence.OutcomeFailed {
			failures = append(failures, r)
		}
		if len(r.ControlIDs) == 0 {
			unmapped++
		}
		for _, id := range r.ControlIDs {
			byControl[id] = append(byControl[id], r)
		}
	}

	if len(failures) > 0 {
		fmt.Fprintf(&b, "## Collection failures\n\n")
		fmt.Fprintf(&b, "Evidence collection did not complete for the items below. "+
			"These gaps are part of the record: during the affected windows no evidence was gathered.\n\n")
		for _, r := range failures {
			fmt.Fprintf(&b, "- %s — collector `%s` failed: %s\n",
				r.CollectedAt.UTC().Format(time.RFC3339), r.CollectorID, r.Error)
		}
		fmt.Fprintf(&b, "\n")
	}

	ids := make([]string, 0, len(byControl))
	for id := range byControl {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	fmt.Fprintf(&b, "## Evidence by control\n\n")
	if len(ids) == 0 {
		fmt.Fprintf(&b, "No evidence is currently mapped to a control.\n\n")
	}
	for _, id := range ids {
		recs := byControl[id]
		if ctrl, ok := e.lookupControl(id); ok {
			fmt.Fprintf(&b, "### %s — %s (%s)\n\n%s\n\n", ctrl.ID, ctrl.Title, ctrl.Article, ctrl.Summary)
		} else {
			fmt.Fprintf(&b, "### %s\n\n", id)
		}
		fmt.Fprintf(&b, "%d evidence record(s). Most recent observations:\n\n", len(recs))
		for _, r := range latestPerTarget(recs, 10) {
			status := "observed"
			if r.Outcome == evidence.OutcomeFailed {
				status = "COLLECTION FAILED"
			}
			fmt.Fprintf(&b, "- %s `%s/%s` (%s) — collector `%s`, record `%s`\n",
				r.CollectedAt.UTC().Format(time.RFC3339), r.Target.Type, r.Target.Name, status, r.CollectorID, r.ID)
		}
		fmt.Fprintf(&b, "\n")
	}

	if unmapped > 0 {
		fmt.Fprintf(&b, "## Unmapped evidence\n\n%d record(s) are not mapped to any control; "+
			"they are retained in the machine-readable bundle.\n\n", unmapped)
	}

	fmt.Fprintf(&b, "---\n\nIntegrity: records form a SHA-256 hash chain; this bundle's manifest lists "+
		"file checksums%s. Verify with `evidenced verify-bundle <dir>`.\n",
		map[bool]string{true: " and an ed25519 signature", false: ""}[e.Key != nil])
	return []byte(b.String())
}

func (e *Exporter) lookupControl(id string) (mapping.Control, bool) {
	if e.Mapping == nil {
		return mapping.Control{}, false
	}
	return e.Mapping.Control(id)
}

// latestPerTarget returns the newest record per target, capped at max,
// newest first.
func latestPerTarget(records []evidence.Record, max int) []evidence.Record {
	latest := map[string]evidence.Record{}
	for _, r := range records {
		key := r.Target.Type + "/" + r.Target.Name
		if cur, ok := latest[key]; !ok || r.CollectedAt.After(cur.CollectedAt) {
			latest[key] = r
		}
	}
	out := make([]evidence.Record, 0, len(latest))
	for _, r := range latest {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CollectedAt.After(out[j].CollectedAt) })
	if len(out) > max {
		out = out[:max]
	}
	return out
}
