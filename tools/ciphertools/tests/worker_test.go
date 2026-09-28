package tests

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/shared"
)

// shared/static/js/cipher-worker.js is the one piece of the engine Go can't run
// natively. These tests run it under jsc, the JavaScriptCore shell that ships
// with macOS, with a stand-in for the Go runtime (what wasm/main.go registers);
// without jsc they skip, as the DB tests do without their BINs. No Node.

const jscMacOS = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"

type workerMsg struct {
	Type  string  `json:"type"`
	ID    int     `json:"id"`
	HTML  *string `json:"html"`
	Error string  `json:"error"`
}

// runWorker loads the worker, inits it, sends one run whose files are fake File
// objects of the given sizes, and returns everything the worker posted. run is
// the stand-in cipherRun; unreadable makes every file's read fail.
func runWorker(t *testing.T, run string, sizes []int, unreadable bool) []workerMsg {
	t.Helper()
	bin := jscMacOS
	if _, err := os.Stat(bin); err != nil {
		if bin, err = exec.LookPath("jsc"); err != nil {
			t.Skip("no jsc (JavaScriptCore shell) on this machine; the worker tests run on macOS")
		}
	}
	src, err := fs.ReadFile(shared.Static, "static/js/cipher-worker.js")
	if err != nil {
		t.Fatal(err)
	}
	sz, _ := json.Marshal(append([]int{}, sizes...))
	prelude := `
var self = globalThis;
var posted = [];
self.postMessage = (m) => posted.push(m);
self.importScripts = () => {};
self.fetch = async () => ({ arrayBuffer: async () => new ArrayBuffer(0) });
WebAssembly.instantiateStreaming = async () => ({ instance: {} });
self.Go = class { constructor() { this.importObject = {}; }
  run() { self.cipherMaxFile = 8; self.cipherRun = ` + run + `; } };
var reads = [];
function file(size) {
  return { size, slice: (a, b) => file(Math.min(b, size) - a),
    arrayBuffer: async () => { if (` + strconv.FormatBool(unreadable) + `) throw new Error("NotReadableError");
      reads.push(size); return new ArrayBuffer(size); } };
}
`
	driver := `
(async () => {
  await self.onmessage({ data: { type: "init", wasm: "w", wasmExec: "x" } });
  await self.onmessage({ data: { type: "run", id: 7, op: "hash", fields: [["text", "abc"]],
    files: ` + string(sz) + `.map((n, i) => ["f" + i, file(n)]) } });
  posted.push({ type: "reads", error: JSON.stringify(reads) });
  print(JSON.stringify(posted));
})().catch((e) => print(JSON.stringify([{ type: "harness", error: String(e) }])));
`
	path := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(path, []byte(prelude+string(src)+driver), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, path).CombinedOutput()
	if err != nil {
		t.Fatalf("jsc: %v\n%s", err, out)
	}
	var msgs []workerMsg
	if err := json.Unmarshal(out, &msgs); err != nil {
		t.Fatalf("worker output %q: %v", out, err)
	}
	return msgs
}

// result returns the one result posted for the run, failing if there isn't
// exactly one: a run with no answer leaves the page's promise pending and its
// submit button disabled for good.
func result(t *testing.T, msgs []workerMsg) string {
	t.Helper()
	var got []workerMsg
	for _, m := range msgs {
		switch m.Type {
		case "failed", "harness":
			t.Fatalf("%s: %s", m.Type, m.Error)
		case "result":
			got = append(got, m)
		}
	}
	if len(got) != 1 || got[0].ID != 7 || got[0].HTML == nil {
		t.Fatalf("want one result with html for run 7, got %+v", msgs)
	}
	return *got[0].HTML
}

// A picked file is read only as far as the engine will take it. A disk image
// read whole was copied into the Go heap, and running out of memory there is a
// fatal error that takes the engine down until a reload.
func TestWorkerReadsAtMostMaxFilePlusOne(t *testing.T) {
	msgs := runWorker(t, `(op, fields, files) => files.map((f) => f[0] + "=" + f[1].length).join(",")`,
		[]int{3, 5_000_000_000}, false)
	if got := result(t, msgs); got != "f0=3,f1=9" {
		t.Errorf("cipherRun saw %q, want f0=3,f1=9 (8-byte limit + 1)", got)
	}
	if reads := msgs[len(msgs)-1].Error; reads != "[3,9]" {
		t.Errorf("reads = %s, want [3,9]", reads)
	}
}

// A Go runtime that exits mid-call makes cipherRun return undefined, not throw;
// the page used to paint the word "undefined".
func TestWorkerReportsEngineExitMidCall(t *testing.T) {
	if got := result(t, runWorker(t, `() => undefined`, nil, false)); !strings.Contains(got, "The engine stopped") {
		t.Errorf("html = %q", got)
	}
}

func TestWorkerAnswersWhenFileCannotBeRead(t *testing.T) {
	got := result(t, runWorker(t, `() => "ran"`, []int{3}, true))
	if !strings.Contains(got, "alert-error") || !strings.Contains(got, "NotReadableError") {
		t.Errorf("html = %q", got)
	}
}
