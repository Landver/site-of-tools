// mail.corpberry.com page glue: runs each form[data-mail] in the client-side engine (mail-worker.js).
// Everything runs locally via WebAssembly: zero bytes of reports, SVGs, or headers sent to any server.
(() => {
  "use strict";

  const box = document.querySelector("[data-mail-engine]");
  if (!box) return;
  box.hidden = false;
  const show = (state) => {
    for (const el of box.querySelectorAll("[data-state]")) el.hidden = el.dataset.state !== state;
  };

  let worker;
  let seq = 0;
  const pending = new Map(); // request id -> resolve
  const ready = new Promise((resolve, reject) => {
    worker = new Worker(box.dataset.worker);
    worker.onmessage = ({ data: m }) => {
      if (m.type === "ready") resolve();
      else if (m.type === "failed") reject(new Error(m.error));
      else if (m.type === "result") {
        pending.get(m.id)?.(m.html);
        pending.delete(m.id);
      }
    };
    worker.onerror = (e) => reject(new Error(e.message || "worker failed"));
    worker.postMessage({ type: "init", wasm: box.dataset.wasm, wasmExec: box.dataset.wasmExec });
  });

  ready.then(() => {
    show("ready");
  }, (err) => {
    show("failed");
    console.error("mail engine:", err);
  });

  const latest = new WeakMap();

  async function run(form, submitter) {
    const target = document.querySelector(form.dataset.target || "#result");
    if (!target) return;
    const id = ++seq;
    latest.set(form, id);
    const button = form.querySelector("button[type=submit]");
    try {
      await ready;
    } catch {
      target.innerHTML = '<div class="alert-error" role="alert">In-browser WASM engine failed to load. Please reload the page.</div>';
      return;
    }

    const fields = [], files = [];
    for (const [k, v] of new FormData(form, submitter)) {
      if (typeof v === "string") fields.push([k, v]);
      else if (v.size > 0) files.push([k, v]);
    }
    if (button) button.disabled = true;
    const html = await new Promise((resolve) => {
      pending.set(id, resolve);
      worker.postMessage({ type: "run", id, op: form.dataset.mail, fields, files });
    });
    if (button) button.disabled = false;
    if (latest.get(form) === id) {
      target.innerHTML = html;
      if (window.innerWidth < 768 && target.getBoundingClientRect().top > window.innerHeight) {
        target.scrollIntoView({ behavior: "smooth" });
      }
    }
  }

  for (const form of document.querySelectorAll("form[data-mail]")) {
    form.addEventListener("submit", (e) => {
      e.preventDefault(); // 100% in-browser WASM: never send to server
      run(form, e.submitter);
    });

    const fileInput = form.querySelector("input[type=file]");
    if (fileInput) {
      fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) run(form);
      });
    }

    const dropZone = form.querySelector("[data-dropzone]") || form;
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.dataset.dragging = "";
    });
    dropZone.addEventListener("dragleave", (e) => {
      if (!dropZone.contains(e.relatedTarget)) delete dropZone.dataset.dragging;
    });
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      delete dropZone.dataset.dragging;
      if (!e.dataTransfer.files.length) return;
      if (fileInput) {
        fileInput.files = e.dataTransfer.files;
        run(form);
      }
    });
  }
})();
