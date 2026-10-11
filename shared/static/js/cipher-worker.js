// Engine host: a Web Worker, since bcrypt, Argon2 or RSA-4096 take seconds. In: init {wasm, wasmExec} | run {id, op,
// fields, files}. Out: ready | failed {error} | result {id, html}, exactly one per run: the page waits on it.
"use strict";

const escapeHTML = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const errorBox = (text) => '<div class="alert-error" role="alert">' + escapeHTML(text) + "</div>";

self.onmessage = async ({ data: m }) => {
  if (m.type === "init") {
    try {
      importScripts(m.wasmExec); // defines Go; must match the compiler that built the .wasm
      const go = new Go();
      let wasm;
      try {
        wasm = await WebAssembly.instantiateStreaming(fetch(m.wasm), go.importObject);
      } catch {
        // Streaming needs an application/wasm content type; the buffered path doesn't.
        wasm = await WebAssembly.instantiate(await (await fetch(m.wasm)).arrayBuffer(), go.importObject);
      }
      go.run(wasm.instance); // runs main() up to its select{}, which registers cipherRun
      if (self.cipherInitError) throw new Error(self.cipherInitError);
      if (typeof self.cipherRun !== "function" || typeof self.cipherMaxFile !== "number") {
        throw new Error("engine started but registered nothing");
      }
      self.postMessage({ type: "ready" });
    } catch (err) {
      self.postMessage({ type: "failed", error: String(err && err.message || err) });
    }
  } else if (m.type === "run") {
    const reply = (html) => self.postMessage({ type: "result", id: m.id, html });
    const files = [];
    try {
      // One byte past cipherMaxFile is enough to refuse a file; read whole, a disk image could exhaust the Go heap.
      for (const [k, f] of m.files) {
        const part = f.size > self.cipherMaxFile ? f.slice(0, self.cipherMaxFile + 1) : f;
        files.push([k, new Uint8Array(await part.arrayBuffer())]);
      }
    } catch (err) {
      return reply(errorBox("Couldn't read the file: " + err + ". Pick it again."));
    }
    let html;
    try {
      html = self.cipherRun(m.op, m.fields, files);
      // A runtime that exits mid-call (out of memory) returns undefined rather than throwing.
      if (typeof html !== "string") throw new Error("Go program has exited");
    } catch (err) {
      html = errorBox("The engine stopped: " + err + ". Reload the page.");
    }
    reply(html);
  }
};
