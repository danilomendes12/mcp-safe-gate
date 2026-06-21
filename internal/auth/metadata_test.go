package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danilomendes/mcpgate/internal/config"
)

func TestBuildResourceMetadataModes(t *testing.T) {
	// Sem resource => sem metadata.
	if m := BuildResourceMetadata(config.Auth{Mode: config.AuthOIDC, OIDC: config.OIDC{Issuer: "https://idp"}}); m != nil {
		t.Error("sem resource deveria devolver nil")
	}
	// apikey não tem authorization server a anunciar.
	if m := BuildResourceMetadata(config.Auth{Mode: config.AuthAPIKey, Resource: "https://gw"}); m != nil {
		t.Error("apikey deveria devolver nil (sem AS)")
	}
	// oidc com issuer + resource => metadata completo.
	m := BuildResourceMetadata(config.Auth{
		Mode:           config.AuthOIDC,
		Resource:       "https://gw.example/mcp",
		RequiredScopes: []string{"tools:call"},
		OIDC:           config.OIDC{Issuer: "https://idp.test"},
	})
	if m == nil {
		t.Fatal("esperava metadata não-nil")
	}
	if m.Resource != "https://gw.example/mcp" {
		t.Errorf("Resource = %q", m.Resource)
	}
	if len(m.AuthorizationServers) != 1 || m.AuthorizationServers[0] != "https://idp.test" {
		t.Errorf("AuthorizationServers = %v", m.AuthorizationServers)
	}
}

func TestMetadataHandlerServesRFC9728(t *testing.T) {
	h := MetadataHandler(config.Auth{
		Mode:     config.AuthOIDC,
		Resource: "https://gw.example/mcp",
		OIDC:     config.OIDC{Issuer: "https://idp.test"},
	})
	if h == nil {
		t.Fatal("handler nil")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ProtectedResourceMetadataPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, quer 200", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("corpo não é JSON: %v", err)
	}
	if got["resource"] != "https://gw.example/mcp" {
		t.Errorf("resource = %v", got["resource"])
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("faltou CORS para discovery do cliente")
	}
}
