// benchserver exposes reproducible workloads. nethttp is a minimal JSON
// baseline; it is not an equivalent-feature validated framework comparison.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/http/pprof"

	jsonv2 "encoding/json/v2"
	"github.com/pyrex41/gfast"
)

type Item struct {
	Name  string `json:"name" required:"true" minLength:"1" maxLength:"80"`
	Count int    `json:"count" ge:"1" le:"100"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8088", "listen address")
	framework := flag.String("framework", "gfast", "gfast or nethttp")
	profile := flag.String("profile", "", "optional separate pprof listener, e.g. 127.0.0.1:6060")
	flag.Parse()
	if *profile != "" {
		m := http.NewServeMux()
		m.HandleFunc("/debug/pprof/", pprof.Index)
		m.HandleFunc("/debug/pprof/profile", pprof.Profile)
		m.HandleFunc("/debug/pprof/trace", pprof.Trace)
		go func() { log.Print(http.ListenAndServe(*profile, m)) }()
	}
	var handler http.Handler
	switch *framework {
	case "gfast":
		app := gfast.New(gfast.Title("Conformance fixture"), gfast.Version("1.0"))
		app.Get("/json", func(context.Context, *struct{}) (*Item, error) { return &Item{Name: "widget", Count: 3}, nil })
		app.Post("/validated", func(_ context.Context, in *struct{ Body Item }) (*Item, error) { return &in.Body, nil })
		app.Get("/query", func(_ context.Context, in *struct {
			Count int `query:"count" ge:"1" le:"100" required:"true"`
		}) (*Item, error) { return &Item{Name: "widget", Count: in.Count}, nil })
		app.Get("/auth", func(context.Context, *struct{}) (*Item, error) { return &Item{Name: "widget", Count: 3}, nil }, gfast.Require(gfast.BearerAuth()))
		handler = app.Handler()
	case "nethttp":
		m := http.NewServeMux()
		m.HandleFunc("GET /json", func(w http.ResponseWriter, r *http.Request) {
			payload, _ := jsonv2.Marshal(&Item{Name: "widget", Count: 3})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(payload)
		})
		handler = m
	default:
		log.Fatalf("unknown framework %q", *framework)
	}
	log.Printf("%s listening on %s", *framework, *addr)
	log.Fatal(http.ListenAndServe(*addr, handler))
}
