package gfast_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/pyrex41/gfast"
)

type specCell struct {
	Name string `json:"name" doc:"Cell name"`
}

type specBody struct {
	Title string     `json:"title" doc:"Item title" example:"coat"`
	N     int        `json:"n" example:"0"`
	On    bool       `json:"on" example:"false"`
	Cells []specCell `json:"cells"`
	Inner struct {
		N int `json:"n"`
	} `json:"inner"`
}

type specCycle struct {
	Name string     `json:"name"`
	Next *specCycle `json:"next"`
}

func TestOpenAPISchemaRefsAndDocument(t *testing.T) {
	app := gfast.New(
		gfast.Title("Items"),
		gfast.Servers(gfast.Server{URL: "https://old.example", Description: "Old"}),
		gfast.Servers(gfast.Server{URL: "https://api.example/v1", Description: "Prod"}),
		gfast.ExternalDocs("https://docs.example/api", "Reference"),
		gfast.TagDescription("items", "Item routes"),
		gfast.Webhooks(map[string]any{
			"newItem": map[string]any{
				"post": map[string]any{"operationId": "newItemHook"},
			},
		}),
		gfast.OpenAPIHook(func(doc map[string]any) {
			info := doc["info"].(map[string]any)
			if info["title"] != "Items" {
				t.Fatalf("hook title %#v", info["title"])
			}
			if _, ok := doc["paths"].(map[string]any)["/items"]; !ok {
				t.Fatalf("hook paths %#v", doc["paths"])
			}
			info["description"] = "edited"
		}),
	)
	hidden := app.Group("/v1", gfast.IncludeInSchema(false), gfast.Deprecated(true))
	app.Post("/items", func(ctx context.Context, in *struct {
		Q    string `query:"q" doc:"Search" example:"hat"`
		Body specBody
	}) (*specBody, error) {
		return &in.Body, nil
	}, gfast.Deprecated(true), gfast.OperationID("createItem"), gfast.Tags("items"),
		gfast.ExternalDocs("https://docs.example/items", "Item"),
		gfast.Callbacks(map[string]any{
			"onEvent": map[string]any{"$ref": "#/components/schemas/specBody"},
		}))
	app.Get("/anon", func(ctx context.Context, in *struct{}) (*struct {
		N int `json:"n"`
	}, error) {
		return nil, nil
	})
	app.Get("/mix", func(ctx context.Context, in *struct{}) (*struct {
		Item specBody `json:"item"`
		N    int      `json:"n"`
	}, error) {
		return nil, nil
	})
	app.Get("/cycle", func(ctx context.Context, in *struct{}) (*specCycle, error) {
		return &specCycle{Name: "a"}, nil
	})
	hidden.Get("/no", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{true}, nil
	})
	hidden.Get("/yes", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{true}, nil
	}, gfast.IncludeInSchema(true), gfast.Deprecated(false), gfast.OperationID("showYes"))
	app.Get("/live", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{true}, nil
	}, gfast.IncludeInSchema(false))

	if res := app.Request(http.MethodGet, "/live", nil); res.Status != http.StatusOK {
		t.Fatalf("hidden route %d %s", res.Status, res.Body)
	}
	if res := app.Request(http.MethodGet, "/v1/no", nil); res.Status != http.StatusOK {
		t.Fatalf("group hidden %d %s", res.Status, res.Body)
	}
	if res := app.Request(http.MethodPost, "/hooks/newItem", []byte(`{}`)); res.Status != http.StatusNotFound {
		t.Fatalf("webhook invoked %d %s", res.Status, res.Body)
	}

	spec := app.Request(http.MethodGet, "/openapi.json", nil)
	if spec.Status != http.StatusOK {
		t.Fatalf("spec %d %s", spec.Status, spec.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(spec.Body, &doc); err != nil {
		t.Fatal(err)
	}
	info := doc["info"].(map[string]any)
	if info["title"] != "Items" || info["description"] != "edited" {
		t.Fatalf("info %#v", info)
	}
	servers := doc["servers"].([]any)
	if len(servers) != 1 || servers[0].(map[string]any)["url"] != "https://api.example/v1" {
		t.Fatalf("servers %#v", servers)
	}
	ext := doc["externalDocs"].(map[string]any)
	if ext["url"] != "https://docs.example/api" || ext["description"] != "Reference" {
		t.Fatalf("externalDocs %#v", ext)
	}
	tags := doc["tags"].([]any)
	if len(tags) != 1 || tags[0].(map[string]any)["name"] != "items" || tags[0].(map[string]any)["description"] != "Item routes" {
		t.Fatalf("tags %#v", tags)
	}
	hook := doc["webhooks"].(map[string]any)["newItem"].(map[string]any)["post"].(map[string]any)
	if hook["operationId"] != "newItemHook" {
		t.Fatalf("webhook %#v", doc["webhooks"])
	}
	paths := doc["paths"].(map[string]any)
	if _, ok := paths["/live"]; ok {
		t.Fatalf("hidden path present")
	}
	if _, ok := paths["/v1/no"]; ok {
		t.Fatalf("group path present")
	}
	yes := paths["/v1/yes"].(map[string]any)["get"].(map[string]any)
	if yes["operationId"] != "showYes" || yes["deprecated"] != nil {
		t.Fatalf("shown child %#v", yes)
	}
	op := paths["/items"].(map[string]any)["post"].(map[string]any)
	if op["operationId"] != "createItem" || op["deprecated"] != true {
		t.Fatalf("operation %#v", op)
	}
	opExt := op["externalDocs"].(map[string]any)
	if opExt["url"] != "https://docs.example/items" {
		t.Fatalf("operation docs %#v", opExt)
	}
	if op["callbacks"].(map[string]any)["onEvent"].(map[string]any)["$ref"] != "#/components/schemas/specBody" {
		t.Fatalf("callbacks %#v", op["callbacks"])
	}
	params := op["parameters"].([]any)
	q := params[0].(map[string]any)
	if q["name"] != "q" || q["description"] != "Search" || q["schema"].(map[string]any)["example"] != "hat" {
		t.Fatalf("query %#v", q)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	bodyRef := op["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	outRef := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if bodyRef["$ref"] != "#/components/schemas/specBody" || outRef["$ref"] != bodyRef["$ref"] {
		t.Fatalf("refs body %#v out %#v", bodyRef, outRef)
	}
	body := schemas["specBody"].(map[string]any)
	props := body["properties"].(map[string]any)
	title := props["title"].(map[string]any)
	if title["description"] != "Item title" || title["example"] != "coat" || title["type"] != "string" {
		t.Fatalf("title %#v", title)
	}
	if props["n"].(map[string]any)["example"] != float64(0) || props["on"].(map[string]any)["example"] != false {
		t.Fatalf("zero examples n %#v on %#v", props["n"], props["on"])
	}
	cellRef := props["cells"].(map[string]any)["items"].(map[string]any)["$ref"]
	if cellRef != "#/components/schemas/specCell" {
		t.Fatalf("cell ref %#v", props["cells"])
	}
	cell := schemas["specCell"].(map[string]any)["properties"].(map[string]any)["name"].(map[string]any)
	if cell["type"] != "string" || cell["description"] != "Cell name" {
		t.Fatalf("cell %#v", cell)
	}
	inner := props["inner"].(map[string]any)
	if inner["$ref"] != nil || inner["type"] != "object" || inner["properties"].(map[string]any)["n"].(map[string]any)["type"] != "integer" {
		t.Fatalf("inner %#v", inner)
	}
	anon := paths["/anon"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if anon["$ref"] != nil || anon["type"] != "object" || anon["properties"].(map[string]any)["n"].(map[string]any)["type"] != "integer" {
		t.Fatalf("anon %#v", anon)
	}
	mix := paths["/mix"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if mix["type"] != "object" || mix["properties"].(map[string]any)["item"].(map[string]any)["$ref"] != "#/components/schemas/specBody" {
		t.Fatalf("mix %#v", mix)
	}
	cycle := schemas["specCycle"].(map[string]any)["properties"].(map[string]any)["next"].(map[string]any)
	if cycle["$ref"] != "#/components/schemas/specCycle" {
		t.Fatalf("cycle %#v", cycle)
	}
	if strings.Contains(string(spec.Body), `"live"`) {
		t.Fatalf("hidden path leaked %s", spec.Body)
	}
}

func TestDocsDisabled(t *testing.T) {
	app := gfast.New(gfast.Docs(false), gfast.Title("Hidden"))
	app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{true}, nil
	})
	if res := app.Request(http.MethodGet, "/ping", nil); res.Status != http.StatusOK {
		t.Fatalf("ping %d %s", res.Status, res.Body)
	}
	for _, path := range []string{"/openapi.json", "/docs", "/docs/", "/docs/swagger-ui.css", "/docs/oauth2-redirect"} {
		res := app.Request(http.MethodGet, path, nil)
		if res.Status != http.StatusNotFound {
			t.Fatalf("%s %d %s", path, res.Status, res.Body)
		}
	}
}
