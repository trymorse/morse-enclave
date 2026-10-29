package worker

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/e2ee"
	"morse/backend/internal/health"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

var faultOutcomes = map[string]struct {
	err  error
	want health.Outcome
}{
	"upstream.ErrUnreachable": {upstream.ErrUnreachable, health.Unreachable},
	"upstream.ErrMalformed":   {upstream.ErrMalformed, health.UpstreamError},
	"upstream.ErrNotFound":    {upstream.ErrNotFound, health.UpstreamError},
	"upstream.ErrNotObject":   {upstream.ErrNotObject, health.UpstreamError},
	"sse.ErrTruncated":        {sse.ErrTruncated, health.UpstreamError},
	"sse.ErrTooLarge":         {sse.ErrTooLarge, health.UpstreamError},
	"e2ee.ErrNotApplied":      {e2ee.ErrNotApplied, health.Unattested},
}

func exportedErrorSentinels(t *testing.T, dir, qualifier string) []string {
	t.Helper()
	pkgs, err := parser.ParseDir(token.NewFileSet(), dir, func(f fs.FileInfo) bool { return !strings.HasSuffix(f.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				vars, ok := decl.(*ast.GenDecl)
				if !ok || vars.Tok != token.VAR {
					continue
				}
				for _, spec := range vars.Specs {
					value := spec.(*ast.ValueSpec)
					for i, name := range value.Names {
						if !strings.HasPrefix(name.Name, "Err") || i >= len(value.Values) {
							continue
						}
						call, ok := value.Values[i].(*ast.CallExpr)
						if !ok {
							continue
						}
						if built, ok := call.Fun.(*ast.SelectorExpr); ok && (built.Sel.Name == "New" || built.Sel.Name == "Errorf") {
							names = append(names, qualifier+"."+name.Name)
						}
					}
				}
			}
		}
	}
	return names
}

func TestEveryUpstreamErrorSentinelHasAClassOfItsOwnChoosing(t *testing.T) {
	var declared []string
	for dir, qualifier := range map[string]string{"../upstream": "upstream", "../sse": "sse", "../e2ee": "e2ee", "../openaicompat": "openaicompat"} {
		declared = append(declared, exportedErrorSentinels(t, dir, qualifier)...)
	}
	if len(declared) < 5 {
		t.Fatalf("found only %v; the walk is not seeing the sentinels", declared)
	}
	for _, name := range declared {
		c, ok := faultOutcomes[name]
		if !ok {
			t.Errorf("%s has no expected class here; decide what it says about the provider and add it to this table", name)
			continue
		}
		if got := health.Classify(evidenceOf(context.Background(), fmt.Errorf("provider: %w", c.err), nil, false)); got != c.want {
			t.Errorf("%s is %s, want %s", name, got, c.want)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(faultOutcomes)) {
		if !slices.Contains(declared, name) {
			t.Errorf("this table names %s, which is no longer declared", name)
		}
	}
}
