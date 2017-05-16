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
	if err == nil || pass != "" {
		t.Fatal("password remove failed")
	}
	strErr := err.Error()
	if strErr == "" || strErr == "Unknown error" {
		t.Fatal("problem exporting error message")
	}
}
