package evidence

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testRecord(name string) Record {
	return Record{
		CollectorID:      "test-collector",
		CollectorVersion: "0.1.0",
		Target: Target{
			Type: "test/target",
			Name: name,
			Attributes: map[string]string{
				"cluster": "dev",
				"zone":    "a",
			},
		},
		CollectedAt: time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Outcome:     OutcomeObserved,
		Observation: json.RawMessage(`{"expiry":"2027-01-01T00:00:00Z","keySize":4096}`),
		ControlIDs:  []string{"DORA-9.2"},
	}
}

func sealedChain(t *testing.T, n int) []Record {
	t.Helper()
	c := NewChain()
	records := make([]Record, 0, n)
	for i := range n {
		r := testRecord(string(rune('a' + i)))
		if err := c.Seal(&r); err != nil {
			t.Fatalf("seal record %d: %v", i, err)
		}
		records = append(records, r)
	}
	return records
}

func TestSealLinksRecords(t *testing.T) {
	records := sealedChain(t, 3)

	if records[0].PrevHash != "" {
		t.Errorf("genesis record PrevHash = %q, want empty", records[0].PrevHash)
	}
	for i, r := range records {
		if r.Hash == "" {
			t.Errorf("record %d: empty hash after seal", i)
		}
		if r.ID == "" {
			t.Errorf("record %d: empty ID after seal", i)
		}
		if i > 0 && r.PrevHash != records[i-1].Hash {
			t.Errorf("record %d: PrevHash = %q, want %q", i, r.PrevHash, records[i-1].Hash)
		}
	}
	if err := Verify(records); err != nil {
		t.Errorf("Verify(untampered chain) = %v, want nil", err)
	}
}

func TestSealIsDeterministic(t *testing.T) {
	a, b := testRecord("x"), testRecord("x")
	a.ID, b.ID = "fixed-id", "fixed-id"
	if err := NewChain().Seal(&a); err != nil {
		t.Fatal(err)
	}
	if err := NewChain().Seal(&b); err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Errorf("identical records hashed differently: %q vs %q", a.Hash, b.Hash)
	}
}

func TestSealRejectsSealedRecord(t *testing.T) {
	r := testRecord("x")
	c := NewChain()
	if err := c.Seal(&r); err != nil {
		t.Fatal(err)
	}
	if err := c.Seal(&r); !errors.Is(err, ErrAlreadySealed) {
		t.Errorf("re-seal error = %v, want ErrAlreadySealed", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(records []Record) []Record
	}{
		{
			name: "modified observation",
			tamper: func(rs []Record) []Record {
				rs[1].Observation = json.RawMessage(`{"expiry":"2099-01-01T00:00:00Z","keySize":4096}`)
				return rs
			},
		},
		{
			name: "modified control ids",
			tamper: func(rs []Record) []Record {
				rs[0].ControlIDs = []string{"DORA-9.2", "DORA-11.1"}
				return rs
			},
		},
		{
			name: "modified timestamp",
			tamper: func(rs []Record) []Record {
				rs[2].CollectedAt = rs[2].CollectedAt.Add(time.Hour)
				return rs
			},
		},
		{
			name: "modified outcome hides a failure",
			tamper: func(rs []Record) []Record {
				rs[1].Outcome = OutcomeFailed
				rs[1].Error = "forged"
				return rs
			},
		},
		{
			name: "record removed from the middle",
			tamper: func(rs []Record) []Record {
				return append(rs[:1], rs[2:]...)
			},
		},
		{
			name: "records reordered",
			tamper: func(rs []Record) []Record {
				rs[0], rs[1] = rs[1], rs[0]
				return rs
			},
		},
		{
			name: "record replaced wholesale",
			tamper: func(rs []Record) []Record {
				forged := testRecord("forged")
				forged.ID = rs[1].ID
				forged.PrevHash = rs[1].PrevHash
				forged.Hash = rs[1].Hash
				rs[1] = forged
				return rs
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := tt.tamper(sealedChain(t, 3))
			if err := Verify(records); !errors.Is(err, ErrTampered) {
				t.Errorf("Verify(tampered chain) = %v, want ErrTampered", err)
			}
		})
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	if err := Verify(nil); err != nil {
		t.Errorf("Verify(nil) = %v, want nil", err)
	}
}

func TestVerifyAfterJSONRoundTrip(t *testing.T) {
	records := sealedChain(t, 3)
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []Record
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := Verify(decoded); err != nil {
		t.Errorf("Verify(round-tripped chain) = %v, want nil", err)
	}
}

func TestResumeContinuesChain(t *testing.T) {
	first := sealedChain(t, 2)

	resumed := Resume(first[len(first)-1].Hash)
	next := testRecord("resumed")
	if err := resumed.Seal(&next); err != nil {
		t.Fatal(err)
	}
	if err := Verify(append(first, next)); err != nil {
		t.Errorf("Verify(resumed chain) = %v, want nil", err)
	}
}

func TestLastHash(t *testing.T) {
	c := NewChain()
	if got := c.LastHash(); got != "" {
		t.Errorf("LastHash() on fresh chain = %q, want empty", got)
	}
	r := testRecord("x")
	if err := c.Seal(&r); err != nil {
		t.Fatal(err)
	}
	if got := c.LastHash(); got != r.Hash {
		t.Errorf("LastHash() = %q, want %q", got, r.Hash)
	}
}
