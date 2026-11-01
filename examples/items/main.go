package main

import (
	"context"
	"net/http"
	"sync"

	"github.com/pyrex41/gfast"
)

// User is the account attached to a request by CurrentUser.
type User struct {
	ID string `json:"id"`
}

// Item is a stored record.
type Item struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Owner string `json:"owner"`
}

// CurrentUser reads the bearer token. The dev token is "dev-token".
// A field tagged gfast:"dep=CurrentUser" receives the value, and the route
// is documented as bearer-protected.
var CurrentUser = gfast.Dep("CurrentUser", func(ctx context.Context, cred gfast.Bearer) (User, error) {
	if cred.Token != "dev-token" {
		return User{}, gfast.Unauthorized("invalid token")
	}
	return User{ID: "u_dev"}, nil
})

type store struct {
	mu    sync.Mutex
	seq   int
	items []Item
}

func (s *store) add(title, owner string) Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	item := Item{ID: itoa(s.seq), Title: title, Owner: owner}
	s.items = append(s.items, item)
	return item
}

func (s *store) list() []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Item, len(s.items))
	copy(out, s.items)
	return out
}

func (s *store) find(id, owner string) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if item.ID == id && item.Owner == owner {
			return item, true
		}
	}
	return Item{}, false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

type listOut struct {
	Items []Item `json:"items"`
}

type createIn struct {
	User User `gfast:"dep=CurrentUser"`
	Body struct {
		Title string `json:"title" minLength:"1" maxLength:"80"`
	}
}

type getIn struct {
	ID   string `path:"id"`
	User User   `gfast:"dep=CurrentUser"`
}

func main() {
	app := newApp()
	if err := app.Run(":8080"); err != nil {
		panic(err)
	}
}

func newApp() *gfast.App {
	items := &store{}
	app := gfast.New(gfast.Title("Items"), gfast.Version("0.1.0"))
	app.Get("/items", func(ctx context.Context, in *struct{}) (*listOut, error) {
		return &listOut{Items: items.list()}, nil
	}, gfast.Summary("List items"))
	app.Post("/items", func(ctx context.Context, in *createIn) (*Item, error) {
		item := items.add(in.Body.Title, in.User.ID)
		return &item, nil
	}, gfast.Summary("Create an item"), gfast.Status(http.StatusCreated))
	app.Get("/items/{id}", func(ctx context.Context, in *getIn) (*Item, error) {
		item, ok := items.find(in.ID, in.User.ID)
		if !ok {
			return nil, gfast.NotFound("item not found")
		}
		return &item, nil
	}, gfast.Summary("Get one item"))
	return app
}
