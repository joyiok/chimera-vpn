package bind

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestExportedAPI is the gomobile contract the Android shell compiles
// against. CI used to shell out to gobind, which prints the Java stubs
// and then exits 1 looking for golang.org/x/mobile/bind inside this
// module. This test pins the Go surface without that extra toolchain.
func TestExportedAPI(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "bind.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	need := map[string]bool{
		"Start":      false,
		"AssignedIP": false,
		"Stop":       false,
		"Send":       false,
		"Receive":    false,
		"SocketFD":   false,
		"IdleMillis": false,
		"BytesSent":  false,
		"BytesRecv":  false,
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !fn.Name.IsExported() {
			continue
		}
		if _, ok := need[fn.Name.Name]; ok {
			need[fn.Name.Name] = true
		}
	}
	for name, seen := range need {
		if !seen {
			t.Errorf("missing exported func %s (gomobile Java/ObjC binding)", name)
		}
	}
}

func TestUnknownHandleErrors(t *testing.T) {
	if _, err := AssignedIP(0); err == nil {
		t.Fatal("AssignedIP(0)")
	}
	if err := Stop(0); err == nil {
		t.Fatal("Stop(0)")
	}
	if err := Send(0, []byte{1}); err == nil {
		t.Fatal("Send(0)")
	}
	if _, err := Receive(0); err == nil {
		t.Fatal("Receive(0)")
	}
	if _, err := SocketFD(0); err == nil {
		t.Fatal("SocketFD(0)")
	}
	if _, err := IdleMillis(0); err == nil {
		t.Fatal("IdleMillis(0)")
	}
	if _, err := BytesSent(0); err == nil {
		t.Fatal("BytesSent(0)")
	}
	if _, err := BytesRecv(0); err == nil {
		t.Fatal("BytesRecv(0)")
	}
}
