package main

import "testing"

func TestWildmat(t *testing.T) {
	m, err := wildmat("*,!control,!control.*,!junk,!alt.binaries.*,alt.binaries.test")
	if err != nil {
		t.Fatal(err)
	}
	for g, want := range map[string]bool{
		"de.test": true, "control": false, "control.cancel": false, "junk": false,
		"alt.binaries.pictures": false, "alt.binaries.test": true, "alt.test": true,
	} {
		if m(g) != want {
			t.Errorf("%s: %v", g, !want)
		}
	}
	none, _ := wildmat("")
	if none("de.test") {
		t.Error("empty list matched")
	}
}

func TestArtNumber(t *testing.T) {
	if n := artNumber("de.comm.internet.commerce:4711"); n != 4711 {
		t.Errorf("%d", n)
	}
}
