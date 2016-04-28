package keychain

import (
	"testing"
)

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

	err = AddInternetPassword(app, "testuser", "dom", "", 0, "https",
		"basic", "password")
	if err != nil {
		t.Fatal(err)
	}
	pass, err = FindInternetPassword(app, "testuser", "", "", 0, "any", "any")
	if err != nil {
		t.Fatal(err)
	}
	if pass != "password" {
		t.Fatalf("password did not match: %s", pass)
	}
	err = RemoveInternetPassword(app, "testuser", "dom", "", 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	pass, err = Find(app, "testuser")
	if err == nil || pass != "" {
		t.Fatal("password remove failed")
	}

}
