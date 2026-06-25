package main

import (
	"reflect"
	"testing"
)

func TestAppendDomainProbeURLs(t *testing.T) {
	got := appendDomainProbeURLs(
		[]string{"https://existing.example.com", "http://example.com"},
		[]string{"example.com", " example.com ", "", "root.example.org"},
	)
	want := []string{
		"https://existing.example.com",
		"http://example.com",
		"https://example.com",
		"http://root.example.org",
		"https://root.example.org",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("appendDomainProbeURLs() = %#v, want %#v", got, want)
	}
}
