package eidc32proxy

import (
	"testing"
)

func TestCanonicalizeHost(t *testing.T) {
	testdata := []string{
		"foo",
		"foo.bar",
		"foo:1",
		"foo.bar:1",
		"foo1",
		"foo1.bar1",
		"foo1:1",
		"foo1.bar1:1",
	}
	expected := []string{
		"foo:443",
		"foo.bar:443",
		"foo:1",
		"foo.bar:1",
		"foo1:443",
		"foo1.bar1:443",
		"foo1:1",
		"foo1.bar1:1",
	}
	for i := range testdata {
		result := canonicalizeHost(testdata[i])
		if result != expected[i] {
			t.Fatalf("canonicalization fail - got '%s', expected '%s'", result, expected[i])
		}
	}

}
