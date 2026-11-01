package main

import (
	"context"
	"net/http"
	"testing"
)

func TestCreateRequiresTokenAndOverrideSkipsIt(t *testing.T) {
	app := newApp()
	missing := app.Request(http.MethodPost, "/items", []byte(`{"title":"Notebook"}`))
	if missing.Status != http.StatusUnauthorized {
		t.Fatalf("missing %d %s", missing.Status, missing.Body)
	}

	created := app.Request(http.MethodPost, "/items", []byte(`{"title":"Notebook"}`), http.Header{
		"Authorization": []string{"Bearer dev-token"},
	})
	if created.Status != http.StatusCreated {
		t.Fatalf("create %d %s", created.Status, created.Body)
	}

	listed := app.Request(http.MethodGet, "/items", nil)
	if listed.Status != http.StatusOK {
		t.Fatalf("list %d %s", listed.Status, listed.Body)
	}

	over := newApp()
	over.Override(CurrentUser, func(ctx context.Context) (User, error) {
		return User{ID: "u_test"}, nil
	})
	got := over.Request(http.MethodPost, "/items", []byte(`{"title":"Override"}`))
	if got.Status != http.StatusCreated {
		t.Fatalf("override %d %s", got.Status, got.Body)
	}
	var item Item
	if err := got.JSON(&item); err != nil {
		t.Fatal(err)
	}
	if item.Owner != "u_test" {
		t.Fatalf("owner %q", item.Owner)
	}
}
