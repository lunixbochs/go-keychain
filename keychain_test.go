package keychain

import "testing"

var app = "github.com/lunixbochs/go-keychain/test"

func TestFlow(t *testing.T) {
	err := Add(app, "testuser", "password")
	if err != nil {
		t.Fatal(err)
	}
	pass, err := Find(app, "testuser")
	if err != nil {
		t.Fatal(err)
	}
	if pass != "password" {
		t.Fatalf("password did not match: %s", pass)
	}
	err = Remove(app, "testuser")
	if err != nil {
		t.Fatal(err)
	}
	pass, err = Find(app, "testuser")
	if err == nil || err.Error() != "The specified item could not be found in the keychain." || pass != "" {
		t.Fatal("password remove failed")
	}
}
