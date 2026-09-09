package internet

import "testing"

// Guards the DialSystem bind fallback. RegisterOutbound only rewrites SocketConfigs
// the wiring was handed; a caller that builds its own (the udphop finalmask) or
// passes none (Xray's internal DNS transports) would otherwise dial off the bound
// interface and, under a sing-box TUN, straight back into the tun.
func TestWithEgressBind(t *testing.T) {
	t.Run("synthesizes a config when the caller has none", func(t *testing.T) {
		got := withEgressBind(nil, "eth0", 42)
		if got == nil {
			t.Fatal("withEgressBind(nil) = nil, want a synthesized config")
		}
		if got.Interface != "eth0" || got.Mark != 42 {
			t.Errorf("got interface %q mark %d, want eth0/42", got.Interface, got.Mark)
		}
	})

	t.Run("clones rather than mutating the caller's config", func(t *testing.T) {
		in := &SocketConfig{Interface: "wlan0", Tfo: 1}
		got := withEgressBind(in, "eth0", 42)
		if got == in {
			t.Fatal("returned the caller's config; a concurrent dial would observe a half-updated one")
		}
		if in.Interface != "wlan0" || in.Mark != 0 {
			t.Errorf("caller's config was mutated: interface %q mark %d", in.Interface, in.Mark)
		}
		if got.Tfo != 1 {
			t.Error("unrelated socket options were dropped by the clone")
		}
	})

	t.Run("returns the same pointer when already bound", func(t *testing.T) {
		in := &SocketConfig{Interface: "eth0", Mark: 42}
		if got := withEgressBind(in, "eth0", 42); got != in {
			t.Error("cloned an already-bound config; registered outbounds re-dial often")
		}
	})

	// Mark 0 means "no auto_redirect to exempt from": a config's own sockopt.mark
	// must survive, matching bindStreamEgress.
	t.Run("a zero mark leaves an existing one alone", func(t *testing.T) {
		in := &SocketConfig{Interface: "eth0", Mark: 7}
		got := withEgressBind(in, "eth0", 0)
		if got != in {
			t.Fatal("cloned when nothing needed changing")
		}
		if got.Mark != 7 {
			t.Errorf("mark = %d, want the config's own 7 preserved", got.Mark)
		}
	})

	t.Run("rebinding to a new interface takes effect", func(t *testing.T) {
		in := &SocketConfig{Interface: "eth0", Mark: 42}
		got := withEgressBind(in, "wlan0", 42)
		if got == in || got.Interface != "wlan0" {
			t.Errorf("got interface %q (same pointer: %v), want a new config on wlan0", got.Interface, got == in)
		}
	})
}

// bindStreamEgress must keep swapping the whole SocketConfig pointer, so a dial
// reading mss.SocketSettings sees either the old config or the new one, never a
// half-updated one.
func TestBindStreamEgressSwapsPointer(t *testing.T) {
	original := &SocketConfig{Interface: "wlan0"}
	mss := &MemoryStreamConfig{SocketSettings: original}

	bindStreamEgress(mss, "eth0", 42)

	if mss.SocketSettings == original {
		t.Fatal("SocketSettings was mutated in place")
	}
	if original.Interface != "wlan0" || original.Mark != 0 {
		t.Errorf("the old config was modified: interface %q mark %d", original.Interface, original.Mark)
	}
	if mss.SocketSettings.Interface != "eth0" || mss.SocketSettings.Mark != 42 {
		t.Errorf("got interface %q mark %d, want eth0/42",
			mss.SocketSettings.Interface, mss.SocketSettings.Mark)
	}
}

func TestBindStateReportsMark(t *testing.T) {
	w := &ThroneWiring{}

	if iface, mark, active := w.bindState(); active || iface != "" || mark != 0 {
		t.Errorf("fresh wiring: got %q/%d/%v, want \"\"/0/false", iface, mark, active)
	}

	w.SetEgress("eth0", 42)
	iface, mark, active := w.bindState()
	if !active || iface != "eth0" || mark != 42 {
		t.Errorf("after SetEgress: got %q/%d/%v, want eth0/42/true", iface, mark, active)
	}

	// The default route going away must keep binding active, so DialSystem's
	// no-interface guard fires instead of silently dialing unbound.
	w.SetEgress("", 42)
	if iface, _, active := w.bindState(); !active || iface != "" {
		t.Errorf("after losing the interface: got %q/%v, want \"\"/true", iface, active)
	}
}
