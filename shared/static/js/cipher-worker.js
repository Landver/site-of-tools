// cipher.corpberry.com engine host — a Web Worker running the Go wasm build of
// tools/ciphertools. Vendored, hand-written, no npm (CLAUDE.md rule #3).
//
// A worker rather than the page because the Go side is synchronous: bcrypt at
// cost 12, Argon2 or an RSA-4096 key take seconds, and on the main thread they
// would freeze the tab for that long.
//
// Messages in:  {type:"init", wasm, wasmExec}   {type:"run", id, op, fields, files}
// Messages out: {type:"ready"} | {type:"failed", error} | {type:"result", id, html}
"use strict";

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
      if (typeof self.cipherRun !== "function") throw new Error("engine started but registered nothing");
      self.postMessage({ type: "ready" });
    } catch (err) {
      self.postMessage({ type: "failed", error: String(err && err.message || err) });
    }
    return;
  }
  if (m.type === "run") {
    let html;
    try {
      html = self.cipherRun(m.op, m.fields, m.files);
    } catch (err) {
      // Go already recovers panics per op; this catches the runtime itself
      // having died, after which every call throws.
      html = '<div class="alert-error" role="alert">The engine stopped: ' +
        String(err).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]) +
        ". Reload the page.</div>";
    }
    self.postMessage({ type: "result", id: m.id, html });
  }
};
