// Mail Engine host: a Web Worker running Go WASM in-browser.
// In: init {wasm, wasmExec} | run {id, op, fields, files}.
// Out: ready | failed {error} | result {id, html}.
"use strict";

const escapeHTML = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const errorBox = (text) => '<div class="alert-error" role="alert">' + escapeHTML(text) + "</div>";

self.onmessage = async ({ data: m }) => {
  if (m.type === "init") {
    try {
      importScripts(m.wasmExec); // defines Go; matches the Go toolchain
      const go = new Go();
      let wasm;
      try {
        wasm = await WebAssembly.instantiateStreaming(fetch(m.wasm), go.importObject);
      } catch {
        wasm = await WebAssembly.instantiate(await (await fetch(m.wasm)).arrayBuffer(), go.importObject);
      }
      go.run(wasm.instance);
      if (self.mailInitError) throw new Error(self.mailInitError);
      if (typeof self.mailRun !== "function") {
        throw new Error("mail engine started but registered no mailRun function");
      }
      self.postMessage({ type: "ready" });
    } catch (err) {
      self.postMessage({ type: "failed", error: String(err && err.message || err) });
    }
  } else if (m.type === "run") {
    const reply = (html) => self.postMessage({ type: "result", id: m.id, html });
    const files = [];
    try {
      const maxFileSize = 10 * 1024 * 1024; // 10 MB limit
      for (const [k, f] of m.files) {
        if (f.size > maxFileSize) {
          return reply(errorBox("File exceeds maximum allowed size of 10 MB."));
        }
        files.push([k, new Uint8Array(await f.arrayBuffer())]);
      }
    } catch (err) {
      return reply(errorBox("Couldn't read file: " + err + ". Pick it again."));
    }
    let html;
    try {
      html = self.mailRun(m.op, m.fields, files);
      if (typeof html !== "string") throw new Error("Go mail engine exited unexpectedly");
    } catch (err) {
      html = errorBox("Engine error: " + err);
    }
    reply(html);
  }
};
