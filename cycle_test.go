package gfast

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestWalkInputAndDepCycles is the registration-time cycle check.
// The child walks one recursive type and must panic with the documented
// message. The parent also walks an acyclic share and a Body cycle in-process.
func TestWalkInputAndDepCycles(t *testing.T) {
	switch os.Getenv("GFAST_WALK") {
	case "input", "dep":
		type Node struct {
			Name string `json:"name"`
			Next *Node  `json:"next"`
		}
		if os.Getenv("GFAST_WALK") == "input" {
			walkInput(reflect.TypeFor[Node](), nil, &inputPlan{}, map[reflect.Type]struct{}{})
		} else {
			var fields []depField
			walkDepFields(reflect.TypeFor[Node](), nil, &fields, map[reflect.Type]struct{}{})
		}
		fmt.Println("GFAST_RESULT registered")
		return
	}
	for _, kind := range []string{"input", "dep"} {
		out, err := walkChild(kind)
		if strings.Contains(out, "GFAST_RESULT registered") || strings.Contains(strings.ToLower(out), "stack overflow") {
			t.Fatalf("%s did not stop: %v %s", kind, err, out)
		}
		if err == nil || !strings.Contains(out, "gfast: recursive type") || !strings.Contains(out, "Node") {
			t.Fatalf("%s panic err %v output %s", kind, err, out)
		}
	}

	type leaf struct {
		Name string `json:"name"`
	}
	type share struct {
		A leaf `json:"a"`
		B leaf `json:"b"`
	}
	walkInput(reflect.TypeFor[share](), nil, &inputPlan{}, map[reflect.Type]struct{}{})
	var shared []depField
	walkDepFields(reflect.TypeFor[share](), nil, &shared, map[reflect.Type]struct{}{})

	type node struct {
		Next *node `json:"next"`
	}
	type body struct {
		Body node
	}
	var plan inputPlan
	walkInput(reflect.TypeFor[body](), nil, &plan, map[reflect.Type]struct{}{})
	if !plan.hasBody {
		t.Fatal("Body was walked as a transport container")
	}
	var fields []depField
	walkDepFields(reflect.TypeFor[body](), nil, &fields, map[reflect.Type]struct{}{})
}

func walkChild(kind string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWalkInputAndDepCycles$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "GFAST_WALK="+kind)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
