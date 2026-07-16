// botcheck collector — vendored, hand-written, no npm (CLAUDE.md rule #3).
//
// Gathers the client-side signals a server can't see (navigator/webdriver/CDP
// traces, WebGL, cross-context UA, permissions, geometry, timezone, high-entropy
// client hints), POSTs them as JSON to /check, and swaps the returned HTML
// fragment into #result. Every probe is wrapped in safe() so one failure never
// aborts collection. Scoring/verdict happens server-side in Go — this only
// collects, it never decides.
(() => {
  "use strict";

  const NATIVE_RE = /\{\s*\[native code\]\s*\}/;

  // Known automation-framework globals; presence of any is a near-standalone tell.
  const WINDOW_MARKERS = [
    "__playwright", "__pw_manual", "__PW_inspect", "_playwright",
    "__nightmare", "_phantom", "callPhantom", "phantom", "__phantomas",
    "domAutomation", "domAutomationController", "_Selenium_IDE_Recorder",
    "__selenium_unwrapped", "__webdriver_evaluate", "__driver_evaluate",
    "__webdriver_script_fn", "__$webdriverAsyncExecutor", "__lastWatirAlert",
    "__fxdriver_unwrapped", "webdriver",
  ];
  const DOC_MARKERS = [
    "$cdc_asdjflasutopfhvcZLmcfl_", "$chrome_asyncScriptInfo",
    "__$webdriverAsyncExecutor", "__webdriver_script_fn",
    "__webdriver_evaluate", "__selenium_evaluate", "__fxdriver_evaluate",
  ];
  const SUSPECT_RE = /(^\$?[cw]dc_)|cdc_|selenium|webdriver|domautomation/i;

  const safe = (fn, fallback) => { try { return fn(); } catch { return fallback; } };

  // cdpTrap: define a getter on an Error's `stack` and hand the Error to the
  // console. A DevTools-Protocol client with Runtime.enable (Puppeteer/Playwright/
  // Selenium 4) — or an open DevTools panel — serializes the object and reads
  // `.stack`, firing the getter; a plain browser never reads it. We must NOT touch
  // `.stack` ourselves, or we'd self-trigger.
  const cdpTrap = () => safe(() => {
    let fired = false;
    const e = new Error();
    Object.defineProperty(e, "stack", { configurable: true, get() { fired = true; return "x"; } });
    try { console.debug(e); } catch {}
    return fired;
  }, false);

  const frameworkGlobals = () => {
    const found = WINDOW_MARKERS.filter((k) => safe(() => typeof window[k] !== "undefined", false))
      .concat(DOC_MARKERS.filter((k) => safe(() => typeof document[k] !== "undefined", false)));
    // Sweep for ChromeDriver's random-suffixed cdc_ key and similar markers.
    safe(() => Object.getOwnPropertyNames(document).forEach((n) => {
      if (SUSPECT_RE.test(n) && !found.includes(n)) found.push(n);
    }));
    return found;
  };

  const nativeToStringOK = () => {
    const tos = Function.prototype.toString;
    const fns = [
      () => tos,
      () => navigator.permissions.query,
      () => HTMLCanvasElement.prototype.toDataURL,
      () => WebGLRenderingContext.prototype.getParameter,
    ].map((f) => safe(f, null)).filter(Boolean);
    return fns.length > 0 && fns.every((fn) => safe(() => NATIVE_RE.test(tos.call(fn)), false));
  };

  const webglRenderer = () => safe(() => {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    const ext = gl?.getExtension("WEBGL_debug_renderer_info");
    return ext ? (gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "") : "";
  }, "");

  // canvasProbe draws the same content twice: identical hashes ⇒ stable; a blank
  // (all-transparent) result ⇒ blocked/headless. Randomised output (unequal
  // hashes) is a noise-injecting anti-fingerprint tool.
  const canvasProbe = () => safe(() => {
    const c = document.createElement("canvas");
    c.width = 60; c.height = 20;
    const ctx = c.getContext("2d");
    if (!ctx) return { canvasSupported: false, canvasStable: true, canvasBlank: false };
    const draw = () => {
      ctx.clearRect(0, 0, 60, 20);
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#069";
      ctx.fillText("Bot✓ 1a", 2, 2);
      ctx.fillStyle = "rgba(102,204,0,0.5)";
      ctx.fillRect(4, 4, 30, 10);
      return c.toDataURL();
    };
    const h1 = draw();
    const h2 = draw();
    let blank = true;
    const data = ctx.getImageData(0, 0, 60, 20).data;
    for (let i = 3; i < data.length; i += 4) { if (data[i] !== 0) { blank = false; break; } }
    return { canvasSupported: true, canvasStable: h1 === h2, canvasBlank: blank };
  }, { canvasSupported: false, canvasStable: true, canvasBlank: false });

  const codecs = () => safe(() => ({
    codecH264: !!document.createElement("video").canPlayType('video/mp4; codecs="avc1.42E01E"'),
    codecAAC: !!document.createElement("audio").canPlayType('audio/mp4; codecs="mp4a.40.2"'),
  }), { codecH264: true, codecAAC: true }); // default true ⇒ a probe failure never flags

  // detectFonts counts how many probe fonts render at a different width than the
  // generic baselines (the classic measureText technique). -1 ⇒ couldn't measure.
  const detectFonts = () => safe(() => {
    const bases = ["monospace", "sans-serif", "serif"];
    const probes = ["Arial", "Courier New", "Times New Roman", "Georgia", "Verdana",
      "Helvetica", "Comic Sans MS", "Trebuchet MS", "Impact", "Menlo", "Tahoma", "Segoe UI"];
    const ctx = document.createElement("canvas").getContext("2d");
    if (!ctx) return -1;
    const w = (font) => { ctx.font = "72px " + font; return ctx.measureText("mmmmmmmmmmlli").width; };
    const baseW = Object.fromEntries(bases.map((b) => [b, w(b)]));
    return probes.filter((p) => bases.some((b) => w(`'${p}',${b}`) !== baseW[b])).length;
  }, -1);

  const iframeUA = () => safe(() => {
    const f = document.createElement("iframe");
    f.style.display = "none";
    document.body.appendChild(f);
    const ua = f.contentWindow.navigator.userAgent;
    f.remove();
    return ua || "";
  }, "");

  // workerProbe recomputes navigator.userAgent and runs the CDP trap inside a Web
  // Worker (a second JS context) — a top-frame-only spoof leaks here. Uses a blob
  // URL so no separate file is needed; resolves with a fallback on timeout/error.
  const workerProbe = () => new Promise((resolve) => {
    const fallback = { ua: "", cdp: false };
    try {
      const src =
        "self.onmessage=()=>{let c=false;const e=new Error();" +
        "try{Object.defineProperty(e,'stack',{get(){c=true;return 'x';}});}catch(_){}" +
        "try{console.debug(e);}catch(_){}self.postMessage({ua:navigator.userAgent,cdp:c});};";
      const url = URL.createObjectURL(new Blob([src], { type: "application/javascript" }));
      const w = new Worker(url);
      const done = (v) => { clearTimeout(timer); safe(() => w.terminate()); URL.revokeObjectURL(url); resolve(v); };
      const timer = setTimeout(() => done(fallback), 800);
      w.onmessage = (ev) => done(ev.data || fallback);
      w.onerror = () => done(fallback);
      w.postMessage("go");
    } catch { resolve(fallback); }
  });

  const uaData = async () => {
    const d = navigator.userAgentData;
    const hi = await safe(
      () => d?.getHighEntropyValues?.(["platform", "platformVersion", "architecture"]),
      null,
    );
    return {
      platform: hi?.platform ?? d?.platform ?? "",
      platform_version: hi?.platformVersion ?? "",
      architecture: hi?.architecture ?? "",
    };
  };

  const permState = () => safe(
    () => navigator.permissions.query({ name: "notifications" }).then((p) => p.state || "", () => ""),
    Promise.resolve(""),
  );

  const collect = async () => {
    const [worker, ua, perm] = await Promise.all([workerProbe(), uaData(), permState()]);
    return {
      webdriver: safe(() => navigator.webdriver === true, false),
      frameworkGlobals: frameworkGlobals(),
      cdpMainThread: cdpTrap(),
      cdpWorker: !!worker.cdp,
      nativeToStringOK: nativeToStringOK(),
      navMainUA: safe(() => navigator.userAgent, ""),
      navWorkerUA: worker.ua || "",
      navIframeUA: iframeUA(),
      languages: safe(() => [...(navigator.languages || [])], []),
      permissionState: perm,
      notificationPermission: safe(() => (typeof Notification !== "undefined" ? Notification.permission : ""), ""),
      hasChromeObject: safe(() => !!window.chrome, false),
      webglRenderer: webglRenderer(),
      plugins: safe(() => navigator.plugins?.length ?? 0, 0),
      screenW: safe(() => screen.width ?? 0, 0),
      screenH: safe(() => screen.height ?? 0, 0),
      outerW: safe(() => window.outerWidth ?? 0, 0),
      innerW: safe(() => window.innerWidth ?? 0, 0),
      hardwareCores: safe(() => navigator.hardwareConcurrency ?? 0, 0),
      deviceMemory: safe(() => navigator.deviceMemory ?? 0, 0),
      browserTZ: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone ?? "", ""),
      uaData: ua,
      language: safe(() => navigator.language ?? "", ""),
      vendor: safe(() => navigator.vendor ?? "", ""),
      appVersion: safe(() => navigator.appVersion ?? "", ""),
      availW: safe(() => screen.availWidth ?? 0, 0),
      availH: safe(() => screen.availHeight ?? 0, 0),
      colorDepth: safe(() => screen.colorDepth ?? 0, 0),
      tzOffset: safe(() => new Date().getTimezoneOffset(), 0),
      brands: safe(() => (navigator.userAgentData?.brands || []).map((b) => b.brand), []),
      fontCount: detectFonts(),
      ...canvasProbe(),
      ...codecs(),
    };
  };

  const runBotCheck = async () => {
    const status = document.getElementById("botcheck-status");
    const result = document.getElementById("result");
    if (status) status.textContent = "collecting…";
    try {
      const res = await fetch("/check", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "text/html" },
        body: JSON.stringify(await collect()),
      });
      if (result) result.innerHTML = await res.text();
      if (status) status.textContent = "";
    } catch {
      if (status) status.textContent = "check failed — try again";
    }
  };

  window.runBotCheck = runBotCheck;
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runBotCheck);
  } else {
    runBotCheck();
  }
})();
