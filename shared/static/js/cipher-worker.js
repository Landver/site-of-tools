// cipher.corpberry.com engine host — a Web Worker running the Go wasm build of
// tools/ciphertools. Vendored, hand-written, no npm (CLAUDE.md rule #3).
//
// A worker rather than the page because the Go side is synchronous: bcrypt at
// cost 12, Argon2 or an RSA-4096 key take seconds, and on the main thread they
// would freeze the tab for that long.
//
// Messages in:  {type:"init", wasm, wasmExec}   {type:"run", id, op, fields, files}
// Messages out: {type:"ready"} | {type:"failed", error} | {type:"result", id, html}
//
// Every run gets exactly one result, whatever fails: the page waits on it, with
// the form's submit button disabled until it comes.
"use strict";

const escapeHTML = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const errorBox = (text) => '<div class="alert-error" role="alert">' + escapeHTML(text) + "</div>";

// files arrive as the page's File objects, unread. Only the first
// cipherMaxFile + 1 bytes of each are read: one past the limit is enough for an
// op to refuse the file, and a disk image read whole would be copied into the
// Go heap, where running out of memory kills the engine (ciphertools.MaxFile).
async function read(files) {
  const out = [];
  for (const [k, f] of files) {
    const part = f.size > self.cipherMaxFile ? f.slice(0, self.cipherMaxFile + 1) : f;
    out.push([k, new Uint8Array(await part.arrayBuffer())]);
  }
  return out;
}

self.onmessage = async (e) => {
  const m = e.data;
  if (m.type === "init") {
    try {
      importScripts(m.wasmExec); // defines Go; must match the compiler that built the .wasm
      const go = new Go();
      let inst;
      try {
        ({ instance: inst } = await WebAssembly.instantiateStreaming(fetch(m.wasm), go.importObject));
      } catch {
        // A server that doesn't send application/wasm breaks streaming; the
        // buffered path doesn't care about the content type.
        const buf = await (await fetch(m.wasm)).arrayBuffer();
        ({ instance: inst } = await WebAssembly.instantiate(buf, go.importObject));
      }
      go.run(inst); // runs main() up to its select{}, which registers cipherRun
      if (self.cipherInitError) throw new Error(self.cipherInitError);
      if (typeof self.cipherRun !== "function" || typeof self.cipherMaxFile !== "number") {
        throw new Error("engine started but registered nothing");
      }
      self.postMessage({ type: "ready" });
    } catch (err) {
      self.postMessage({ type: "failed", error: String(err && err.message || err) });
    }
    return;
  }
  if (m.type === "run") {
    let files;
    try {
      files = await read(m.files);
    } catch (err) {
      // A file changed or removed since it was picked.
      self.postMessage({ type: "result", id: m.id, html: errorBox("Couldn't read the file: " + err + ". Pick it again.") });
      return;
    }
    let html;
    try {
      html = self.cipherRun(m.op, m.fields, files);
      // A runtime that exits during the call (out of memory, a fatal error)
      // returns undefined rather than throwing; only later calls throw.
      if (typeof html !== "string") throw new Error("Go program has exited");
    } catch (err) {
      // Go already recovers panics per op; this catches the runtime itself
      // having died.
      html = errorBox("The engine stopped: " + err + ". Reload the page.");
    }
    self.postMessage({ type: "result", id: m.id, html });
  }
};
