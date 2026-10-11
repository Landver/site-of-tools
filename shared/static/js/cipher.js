// cipher.corpberry.com page glue: runs each form[data-cipher] in the in-browser engine (cipher-worker.js).
// If the engine isn't running NOTHING is sent: no server fallback, since "runs in your browser" is the promise.
(() => {
  "use strict";

  const box = document.querySelector("[data-cipher-engine]");
  if (!box) return;
  box.hidden = false;
  const show = (state) => {
    for (const el of box.querySelectorAll("[data-state]")) el.hidden = el.dataset.state !== state;
  };

  let worker;
  let seq = 0;
  const pending = new Map(); // request id -> resolve
  const ready = new Promise((resolve, reject) => {
    worker = new Worker(box.dataset.worker); // a throw here rejects ready
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
    // A live form answers every keystroke; its submit button stays only for the no-JS path.
    for (const b of document.querySelectorAll("form[data-cipher][data-live] button[type=submit]")) {
      const note = document.createElement("span");
      note.className = "text-xs text-faint";
      note.textContent = "Updates as you type.";
      b.replaceWith(note);
    }
  }, (err) => {
    show("failed");
    console.error("cipher engine:", err);
  });

  // Only the newest request per form may paint: a slow bcrypt must not overwrite a newer keystroke's result.
  const latest = new WeakMap();

  async function run(form, submitter) {
    const target = document.querySelector(form.dataset.target);
    if (!target) return;
    const id = ++seq;
    latest.set(form, id);
    const button = form.querySelector("button[type=submit]");
    try {
      await ready;
    } catch {
      target.innerHTML = "";
      return; // the status line already says it failed; nothing was sent
    }
    // Files go as File objects, unread: the worker reads only as much as the engine takes.
    const fields = [], files = [];
    for (const [k, v] of new FormData(form, submitter)) {
      if (typeof v === "string") fields.push([k, v]);
      else if (v.size > 0) files.push([k, v]);
    }
    if (button) button.disabled = true;
    const html = await new Promise((resolve) => {
      pending.set(id, resolve);
      worker.postMessage({ type: "run", id, op: form.dataset.cipher, fields, files });
    });
    if (button) button.disabled = false;
    if (latest.get(form) === id) target.innerHTML = html; // Alpine's MutationObserver picks up any x-data inside
  }

  // Identify's "Open" links carry the value in sessionStorage, never the URL (history, Referer, logs): it may be a secret.
  const CARRY = "cipher-carry";
  document.addEventListener("click", (e) => {
    const a = e.target.closest("a[data-carry]");
    const src = a && document.querySelector(a.dataset.carrySource);
    if (!src) return;
    try {
      sessionStorage.setItem(CARRY, JSON.stringify({
        path: a.pathname, field: a.dataset.carry, set: a.dataset.carrySet || "", value: src.value,
      }));
    } catch { /* storage off: the link still opens the page */ }
  });
  try {
    const c = JSON.parse(sessionStorage.getItem(CARRY) || "null");
    sessionStorage.removeItem(CARRY);
    const field = c && c.path === location.pathname && document.querySelector("form[data-cipher] [name=\"" + c.field + "\"]");
    if (field) {
      field.value = c.value;
      for (const [k, v] of new URLSearchParams(c.set)) { // "from=hex": the encoding it was recognised as
        const el = field.form.querySelector("[name=\"" + k + "\"]");
        if (el) el.value = v;
      }
      field.focus();
    }
  } catch { /* nothing carried */ }

  for (const form of document.querySelectorAll("form[data-cipher]")) {
    form.addEventListener("submit", (e) => {
      e.preventDefault(); // never post: see the file comment
      run(form, e.submitter);
    });
    if (form.hasAttribute("data-live")) {
      let timer;
      const live = () => { clearTimeout(timer); timer = setTimeout(() => run(form), 150); };
      form.addEventListener("input", live);
      form.addEventListener("change", live);
      // A value already there (back-navigation, a no-JS re-render) gets its result without a keystroke.
      const typed = form.querySelectorAll("textarea, input:not([type]), input[type=text]");
      if ([...typed].some((el) => el.value.trim() !== "")) live();
    }
    // A file dropped anywhere on the form goes into its file input; data-dragging drives the outline.
    const input = form.querySelector("input[type=file]");
    if (!input) continue;
    form.addEventListener("dragover", (e) => {
      e.preventDefault();
      form.dataset.dragging = "";
    });
    form.addEventListener("dragleave", (e) => {
      if (!form.contains(e.relatedTarget)) delete form.dataset.dragging;
    });
    form.addEventListener("drop", (e) => {
      e.preventDefault();
      delete form.dataset.dragging;
      if (!e.dataTransfer.files.length) return;
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
  }
})();
