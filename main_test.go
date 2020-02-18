package main

import (
	"testing"
)

func TestParseTarget(t *testing.T) {

	var tests = []struct {
		input       string
		output      string
		shouldError bool
	}{
		{"https://example.com", "example.com:443", false},
		{"ldaps://example.com", "example.com:636", false},
		{"https://example.com:1234", "example.com:1234", false},
		{"example.com:1234", "example.com:1234", false},
		{"", "", true},
		{"example.com", "", true},
		{"//example.com", "", true},
		{"foobar://example.com", "", true},
	}

	for _, test := range tests {
		res, err := parseTarget(test.input)
		if res != test.output {
			t.Errorf("got %s, should be %s", res, test.output)
		}
		if test.shouldError && err == nil {
			t.Errorf("input %s didn't error, but it should", res)
		}
	}
}
