package utils

import (
	"reflect"
	"testing"
)

func TestNormalizeTargetInputs(t *testing.T) {
	t.Parallel()

	input := []string{
		" 192.168.1.1 ",
		"\thttps://example.com/path \r",
		"",
		"   ",
		"192.168.1.1",
		"[*] WebTitle https://192.168.1.2 code:200 title:Example ",
	}
	want := []string{
		"192.168.1.1",
		"https://example.com/path",
		"[*] WebTitle https://192.168.1.2 code:200 title:Example",
	}

	got := NormalizeTargetInputs(input)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeTargetInputs() = %#v, want %#v", got, want)
	}
}

func TestNormalizeTargetInputsReturnsEmptySlice(t *testing.T) {
	t.Parallel()

	got := NormalizeTargetInputs([]string{"", " \t ", "\r\n"})
	if len(got) != 0 {
		t.Fatalf("NormalizeTargetInputs() = %#v, want an empty slice", got)
	}
}
