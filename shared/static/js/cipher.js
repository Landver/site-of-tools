// cipher.corpberry.com page glue — vendored, hand-written, no npm (CLAUDE.md
// rule #3).
//
// Runs every form marked data-cipher="<op>" inside the in-browser engine (Go
// compiled to wasm, hosted by cipher-worker.js) instead of posting it, then
// puts the returned HTML fragment into the form's data-target. The fragment is
// rendered by the same html/template the server uses, so it is escaped the same
// way; nothing here builds markup from input.
//
// The one rule this file exists to keep: if the engine isn't running, NOTHING
// is sent. There is no fallback to the server, because "runs in your browser"
// is the promise the page makes (tools/ciphertools/docs/02-build-plan.md).
(() => {
  "use strict";

  const box = document.querySelector("[data-cipher-engine]");
  if (!box) return;
  box.hidden = false;

  const show = (state) => {
    for (const el of box.querySelectorAll("[data-state]")) el.hidden = el.dataset.state !== state;
  };

  let worker;
  const pending = new Map(); // request id -> resolve
  let seq = 0;

  const ready = new Promise((resolve, reject) => {
    try {
      worker = new Worker(box.dataset.worker);
    } catch (err) {
      reject(err);
      return;
    }
    worker.onmessage = (e) => {
      const m = e.data;
      if (m.type === "ready") resolve();
      else if (m.type === "failed") reject(new Error(m.error));
      else if (m.type === "result") {
        const done = pending.get(m.id);
        pending.delete(m.id);
        if (done) done(m.html);
      }
    };
    worker.onerror = (e) => reject(new Error(e.message || "worker failed"));
    worker.postMessage({ type: "init", wasm: box.dataset.wasm, wasmExec: box.dataset.wasmExec });
  });
  ready.then(() => {
    show("ready");
    // A live form answers on every keystroke, so its submit button would only
    // suggest a click is needed. It stays in the markup for the no-JS path and
    // is swapped for a note once the engine is known to be running.
    for (const form of document.querySelectorAll("form[data-cipher][data-live]")) {
      for (const b of form.querySelectorAll("button[type=submit]")) {
        const note = document.createElement("span");
        note.className = "text-xs text-faint";
        note.textContent = "Updates as you type.";
        b.replaceWith(note);
      }
    }
  }, (err) => {
    show("failed");
    console.error("cipher engine:", err);
  });

  // FormData -> the plain arrays a worker message can carry. Files go as the
  // File objects, unread (cloning one copies no bytes): the worker reads only as
  // much of each as the engine takes, so a multi-GB pick costs nothing here.
  function collect(form, submitter) {
    const fields = [];
    const files = [];
    for (const [k, v] of new FormData(form, submitter)) {
      if (typeof v === "string") fields.push([k, v]);
      else if (v.size > 0) files.push([k, v]);
    }
    return { fields, files };
  }

  // Only the newest request per form may paint: a slow bcrypt finishing after
  // a newer keystroke's result must not overwrite it.
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
    const { fields, files } = collect(form, submitter);
    if (button) button.disabled = true;
    const html = await new Promise((resolve) => {
      pending.set(id, resolve);
      worker.postMessage({ type: "run", id, op: form.dataset.cipher, fields, files });
    });
    if (button) button.disabled = false;
    if (latest.get(form) !== id) return;
    target.innerHTML = html; // Alpine's MutationObserver picks up any x-data inside
  }

  const debounce = (fn, ms) => {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  };

  // Drop a file anywhere on a form that takes one: fewer clicks than the
  // picker. The dropped file goes into the form's own file input, so it is read
  // by the engine exactly like a picked one. data-dragging drives the outline
  // (a data-dragging: variant in the template, not a class set here).
  for (const form of document.querySelectorAll("form[data-cipher]")) {
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

  // Carry a value to the page that handles it (Identify's "Open" links), so
  // nothing is pasted twice. It travels in sessionStorage, never the URL: a
  // URL is history, Referer and a log line, and the value may be a secret.
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
      // "from=hex": the encoding the value was recognised as, set beside it.
      for (const pair of c.set.split("&").filter(Boolean)) {
        const [k, v] = pair.split("=");
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
      const live = debounce(() => run(form), 150);
      form.addEventListener("input", live);
      form.addEventListener("change", live);
      // A value already in the form (a back-navigation, a no-JS re-render)
      // gets its result without waiting for a keystroke.
      const typed = form.querySelectorAll("textarea, input:not([type]), input[type=text]");
      if ([...typed].some((el) => el.value.trim() !== "")) live();
    }
  }
})();
