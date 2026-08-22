package mapping

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/ssyno/evidenced/evidence"
)

// Control is one regulatory control evidence can be mapped to.
type Control struct {
	ID      string `yaml:"id" json:"id"`
	Article string `yaml:"article" json:"article"`
	Title   string `yaml:"title" json:"title"`
	Summary string `yaml:"summary" json:"summary"`
}

// Rule maps evidence produced by a collector (optionally narrowed to one
// target type) to one or more control IDs.
type Rule struct {
	Collector  string   `yaml:"collector"`
	TargetType string   `yaml:"targetType,omitempty"` // empty matches every target type
	Controls   []string `yaml:"controls"`
}

// Mapping is a full framework mapping: the control catalog plus the rules
// that connect collector output to it. Frameworks ship this as YAML data
// (see internal/mapping/dora); nothing framework-specific lives in Go.
type Mapping struct {
	Framework string    `yaml:"framework"`
	Controls  []Control `yaml:"controls"`
	Rules     []Rule    `yaml:"rules"`

	byID map[string]Control
}

// LoadMapping parses and validates a YAML framework mapping.
func Load(data []byte) (*Mapping, error) {
	var m Mapping
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse mapping: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Mapping) validate() error {
	if m.Framework == "" {
		return fmt.Errorf("mapping has no framework name")
	}
	m.byID = make(map[string]Control, len(m.Controls))
	for _, c := range m.Controls {
		if c.ID == "" {
			return fmt.Errorf("framework %s: control with empty id", m.Framework)
		}
		if _, dup := m.byID[c.ID]; dup {
			return fmt.Errorf("framework %s: duplicate control id %q", m.Framework, c.ID)
		}
		m.byID[c.ID] = c
	}
	for i, r := range m.Rules {
		if r.Collector == "" {
			return fmt.Errorf("framework %s: rule %d has no collector", m.Framework, i)
		}
		if len(r.Controls) == 0 {
			return fmt.Errorf("framework %s: rule %d maps to no controls", m.Framework, i)
		}
		for _, id := range r.Controls {
			if _, ok := m.byID[id]; !ok {
				return fmt.Errorf("framework %s: rule %d references unknown control %q", m.Framework, i, id)
			}
		}
	}
	return nil
}

// Apply sets r.ControlIDs from the rules matching its collector and
// target type. Must be called before the record is sealed.
func (m *Mapping) Apply(r *evidence.Record) {
	seen := map[string]bool{}
	var ids []string
	for _, rule := range m.Rules {
		if rule.Collector != r.CollectorID {
			continue
		}
		if rule.TargetType != "" && rule.TargetType != r.Target.Type {
			continue
		}
		for _, id := range rule.Controls {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	r.ControlIDs = ids
}

// Control looks up a control by ID.
func (m *Mapping) Control(id string) (Control, bool) {
	c, ok := m.byID[id]
	return c, ok
}
