package loreadapter

import "testing"

func TestValidateNameAllowsLeadingDigit(t *testing.T) {
	if err := validateName("2199"); err != nil {
		t.Fatal(err)
	}
	if err := validateName("has space"); err == nil {
		t.Fatal("space accepted")
	}
}
