package builtin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultRegistersEveryCheck is a drift guard, in the same spirit as the
// workflow action-pin test: it walks this package's own source, finds every
// type that implements the check contract (a value receiver Meta() method), and
// fails if any of them is missing from Default().
//
// Without this, adding a check is a two-step operation where step two is easy to
// forget — and forgetting it is silent. That is precisely how the adversarial
// corpus ran for several releases without VC-002f.
func TestDefaultRegistersEveryCheck(t *testing.T) {
	declared := checkTypesInPackage(t)
	if len(declared) == 0 {
		t.Fatal("found no check types in package source — the scanner is broken, not the registry")
	}

	registered := map[string]bool{}
	for _, m := range Default().Metas() {
		registered[m.ID] = true
	}

	for typeName, id := range declared {
		if id == "" {
			t.Errorf("%s has a Meta() but no recognizable check ID literal", typeName)
			continue
		}
		if !registered[id] {
			t.Errorf("check %s (%s) implements Meta() but is NOT in builtin.Default() — "+
				"it is dead code in production and invisible to the adversarial corpus", typeName, id)
		}
	}

	if len(registered) != len(declared) {
		t.Errorf("Default() registers %d checks but the package declares %d; "+
			"a duplicate or stray registration is likely", len(registered), len(declared))
	}
}

// checkTypesInPackage maps type name -> check ID for every type in this package
// that declares a Meta() method returning a check.Meta with an ID field.
func checkTypesInPackage(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]string{}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Meta" || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			recv := receiverTypeName(fn.Recv.List[0].Type)
			if recv == "" {
				continue
			}
			out[recv] = checkIDLiteral(fn)
		}
	}
	return out
}

func receiverTypeName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return receiverTypeName(v.X)
	}
	return ""
}

// checkIDLiteral pulls the ID: "VC-00x" string out of the composite literal the
// Meta() method returns.
func checkIDLiteral(fn *ast.FuncDecl) string {
	var id string
	ast.Inspect(fn, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "ID" {
			return true
		}
		lit, ok := kv.Value.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		id = strings.Trim(lit.Value, `"`)
		return false
	})
	return id
}
