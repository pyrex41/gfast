package gfast

import (
	"embed"
	"net/http"
)

// Swagger UI 5.34.1, Apache-2.0, SmartBear. The files live in
// third_party/swagger-ui and are compiled into the binary, so /docs works
// with no extra install and no call out to a CDN.

//go:embed third_party/swagger-ui/swagger-ui.css third_party/swagger-ui/swagger-ui-bundle.js third_party/swagger-ui/swagger-ui-standalone-preset.js
var swaggerFiles embed.FS

const swaggerDir = "third_party/swagger-ui/"

var swaggerTypes = map[string]string{
	"swagger-ui.css":                  "text/css; charset=utf-8",
	"swagger-ui-bundle.js":            "text/javascript; charset=utf-8",
	"swagger-ui-standalone-preset.js": "text/javascript; charset=utf-8",
}

func registerDocs(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /docs", app.serveDocs)
	mux.HandleFunc("GET /docs/{$}", app.serveDocs)
	mux.HandleFunc("GET /docs/{file}", app.serveDocFile)
}

func (a *App) serveDocs(w http.ResponseWriter, _ *http.Request) {
	title := htmlText(a.doc.Info.Title)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>` + title + `</title>
<link rel="stylesheet" href="/docs/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="/docs/swagger-ui-bundle.js"></script>
<script src="/docs/swagger-ui-standalone-preset.js"></script>
<script>
window.ui = SwaggerUIBundle({
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
  layout: "StandaloneLayout"
});
</script>
</body>
</html>
`))
}

func (a *App) serveDocFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	ctype, ok := swaggerTypes[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := swaggerFiles.ReadFile(swaggerDir + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
