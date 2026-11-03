package gfast

import (
	"fmt"
	"testing"
	"time"

	"hegel.dev/go/hegel"
)

// The model is a ledger of issuance/consumption/expiry events, independent of
// the server's maps and sweep implementation. Hegel shrinks command sequences.
func TestPropOAuthCommandSequences(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		capacity := hegel.Draw(ht, hegel.Integers(1, 4))
		commands := hegel.Draw(ht, hegel.Lists(hegel.Integers(0, 7)).MinSize(1).MaxSize(80))
		now := time.Unix(1000, 0)
		s := contractOAuth(func() time.Time { return now }, capacity)
		type entry struct {
			raw      string
			expires  time.Time
			consumed bool
		}
		var ledger []entry
		for step, command := range commands {
			switch command {
			case 0, 1, 2:
				live := 0
				for _, e := range ledger {
					if !e.consumed && now.Before(e.expires) {
						live++
					}
				}
				issued, err := s.issue(fmt.Sprint(step), "client", nil, true)
				if (err == nil) != (live < capacity) {
					ht.Fatalf("step %d capacity=%d live=%d error=%v", step, capacity, live, err)
				}
				if err == nil {
					ledger = append(ledger, entry{raw: issued.RefreshToken, expires: now.Add(s.refreshTTL)})
				}
			case 3, 4, 5, 6:
				if len(ledger) == 0 {
					continue
				}
				idx := hegel.Draw(ht, hegel.Integers(0, len(ledger)-1))
				e := &ledger[idx]
				client := "client"
				if command == 6 {
					client = "wrong-client"
				}
				want := client == "client" && !e.consumed && now.Before(e.expires)
				got := s.consumeRefresh(e.raw, client)
				if (got != nil) != want {
					ht.Fatalf("step %d consume=%v want=%v", step, got != nil, want)
				}
				if want {
					e.consumed = true
				}
			case 7:
				now = now.Add(s.refreshTTL)
			}
			if len(s.refreshes) > capacity {
				ht.Fatalf("capacity exceeded at step %d", step)
			}
		}
	}, hegel.WithDatabase("hegel-db"))
}
