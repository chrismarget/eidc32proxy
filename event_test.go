package eidc32proxy

import (
	"testing"
)

func TestString(t *testing.T) {
	testData := []EventType{50, 32818, 0, 32768}
	expected := []string{"Authentication_UnknownCard",
		"(Authentication_UnknownCard)",
		"Unknown_Event_Type",
		"(Unknown_Event_Type)",
	}
	for i := range testData {
		result := testData[i].String()
		if result != expected[i] {
			t.Fatalf("expected %s, got %s", expected[i], result)
		}
	}
}
