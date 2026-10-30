package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionDoesNotRequireDockerOrBootstrap(t *testing.T) {
	var output, diagnostic bytes.Buffer
	if err := run([]string{"version"}, &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), version) {
		t.Fatal(output.String())
	}
}

func TestMissingCommandFailsBeforeAccessingHost(t *testing.T) {
	var output, diagnostic bytes.Buffer
	if err := run(nil, &output, &diagnostic); err == nil {
		t.Fatal("missing command succeeded")
	}
	if output.Len() != 0 {
		t.Fatal("unexpected output")
	}
}
