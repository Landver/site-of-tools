// botcheck collector — vendored, hand-written, no npm (CLAUDE.md rule #3).
//
// Gathers the client-side signals a server can't see (navigator/webdriver/CDP
// traces, the WebGL GPU vendor+renderer, cross-context navigator values from a
// Web Worker / iframe / Service Worker, permissions, geometry, timezone, the
// userAgentData version list, a feature-detected engine family, and engine
// constants like navigator.productSub), POSTs them as JSON to /check, and swaps
// the returned HTML fragment into #result. Every probe is wrapped in safe() so
// one failure never aborts collection. Scoring/verdict happens server-side in
// Go — this only collects, it never decides.
(() => {
  "use strict";

  const NATIVE_RE = /\{\s*\[native code\]\s*\}/;

  // Known automation-framework globals; presence of any is a near-standalone tell.
  // Only AUTOMATION-only markers belong here: embedded-runtime markers
  // (CefSharp/Awesomium/CEF) are deliberately excluded — legit desktop apps embed
  // those engines, and the UA-side embedded_runtime rule already covers that class.
  const WINDOW_MARKERS = [
    "__playwright", "__pw_manual", "__PW_inspect", "_playwright",
    "__pwInitScripts", "__playwright__binding__", // Playwright binding hooks
    "__nightmare", "_phantom", "callPhantom", "phantom", "__phantomas",
    "domAutomation", "domAutomationController", "_Selenium_IDE_Recorder",
    "__selenium_unwrapped", "__webdriver_evaluate", "__driver_evaluate",
    "__webdriver_script_fn", "__$webdriverAsyncExecutor", "__lastWatirAlert",
    "__fxdriver_unwrapped", "webdriver",
    // G13: the wider Selenium/Watir canon from the intoli/fp-scanner lineage that
    // BrowserScan/sannysoft check individually.
    "__webdriver_unwrapped", "__driver_unwrapped", "__webdriver_script_function",
    "__webdriver_script_func", "_selenium", "calledSelenium", "_WEBDRIVER_ELEM_CACHE",
    "ChromeDriverw", "driver-evaluate", "webdriver-evaluate", "selenium-evaluate",
    "webdriverCommand", "webdriver-evaluate-response",
    "__lastWatirConfirm", "__lastWatirPrompt", "_watir",
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
    // Sweep for ChromeDriver's random-suffixed cdc_ key and similar markers — over
    // both document and window own property names (G17): an injected automation
    // global the explicit lists miss still surfaces here.
    for (const obj of [document, window]) {
      safe(() => Object.getOwnPropertyNames(obj).forEach((n) => {
        if (SUSPECT_RE.test(n) && !found.includes(n)) found.push(n);
      }));
    }
    // Sequentum's scraping runtime brands window.external (fp-scanner's SEQUENTUM
    // check; deviceandbrowserinfo's isSequentum reads the same string).
    safe(() => {
      const ext = window.external;
      if (ext && /sequentum/i.test(String(ext))) found.push("sequentum (window.external)");
    });
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

  // ── G04: deep native-tamper / lie detection (CreepJS queryLies-style) ───────
  // The shallow nativeToStringOK() above only regexes toString output; stealth
  // toolkits (puppeteer-extra-stealth) defeat exactly that by swapping
  // Function.prototype.toString for a Proxy that lies about patched functions.
  // These probes look for what a lie can't hide: impossible property descriptors,
  // missing call/new TypeError traps, and Proxy artifacts. Same convention as
  // codecs(): a probe that can't run or throws yields the PASS value — never flag
  // on doubt.

  // hasOwn is Object.hasOwn with a fail-safe: if it can't run (a very old engine),
  // "absent" is the conservative answer for every use below.
  const hasOwn = (o, k) => safe(() => Object.hasOwn(o, k), false);

  // findOwner walks the prototype chain to the object that actually owns prop —
  // the descriptor must be read where the property lives, not assumed to sit on
  // the expected prototype (a patch may install an own property on the instance).
  const findOwner = (obj, prop) => {
    let o = obj;
    while (o && !Object.prototype.hasOwnProperty.call(o, prop)) o = Object.getPrototypeOf(o);
    return o;
  };

  // threwTypeError reports whether fn throws specifically a TypeError — the ONLY
  // thing the traps below assert (messages are engine-specific).
  const threwTypeError = (fn) => {
    try { fn(); return false; } catch (e) { return e instanceof TypeError; }
  };

  // Descriptor / own-property sanity on the same natives nativeToStringOK checks.
  // A genuine native method is a writable / configurable DATA property on its
  // prototype, carries no own 'prototype' (non-constructors), 'arguments' or
  // 'caller', and keeps the spec-mandated name/length — a monkey-patch (a plain
  // or bound function, or a defineProperty with the wrong flags) breaks at least
  // one of these. Enumerability differs BY SPEC and is asserted per target:
  // ECMA-262 built-ins (Function.prototype.toString) are non-enumerable, while
  // WebIDL operations (permissions.query, toDataURL, getParameter) are always
  // enumerable — asserting one family's shape on the other false-fires every
  // real browser. Absent APIs are skipped like nativeToStringOK does; any probe
  // failure yields true.
  const nativeDescriptorsOK = () => safe(() => {
    // [holder, property, expected name, expected length, expected enumerable]
    const targets = [
      [Function.prototype, "toString", "toString", 0, false], // ECMA-262 built-in
      [safe(() => navigator.permissions, null), "query", "query", 1, true], // WebIDL op
      [safe(() => HTMLCanvasElement.prototype, null), "toDataURL", "toDataURL", 0, true], // WebIDL op
      [safe(() => WebGLRenderingContext.prototype, null), "getParameter", "getParameter", 1, true], // WebIDL op
    ];
    let checked = 0;
    const ok = targets.every(([obj, prop, name, len, enumerable]) => {
      if (!obj) return true; // API not offered by this browser ⇒ nothing to check
      const owner = findOwner(obj, prop);
      const d = owner && safe(() => Object.getOwnPropertyDescriptor(owner, prop), null);
      if (!d) return true; // property gone entirely ⇒ skip, same as an absent API
      checked++;
      if (typeof d.value !== "function") return false; // turned into a getter/data lie
      return d.writable === true && d.enumerable === enumerable && d.configurable === true &&
        d.value.name === name && d.value.length === len &&
        !hasOwn(d.value, "prototype") && !hasOwn(d.value, "arguments") && !hasOwn(d.value, "caller");
    });
    return checked > 0 && ok;
  }, true);

  // call/new TypeError traps: platform objects reject wrong invocations in ways a
  // JS monkey-patch almost never reproduces — a patch written as a plain function
  // is constructable, and never brand-checks its receiver. Each trap asserts ONLY
  // that a TypeError is thrown; a trap that can't run resolves to pass.
  const nativeCallNewOK = () => safe(() => {
    const traps = [
      // A WebIDL operation is not a constructor: `new query()` must throw.
      () => typeof navigator === "undefined" || !navigator.permissions ||
        threwTypeError(() => new (navigator.permissions.query)()),
      // A platform class constructor called WITHOUT new must throw ("Illegal
      // constructor"); a JS shim commonly forgets to enforce it.
      () => typeof HTMLElement !== "function" ||
        threwTypeError(() => HTMLElement()),
      // A WebIDL method brand-checks its receiver: a foreign `this` must throw
      // ("Illegal invocation"); a plain-function patch never checks.
      () => typeof HTMLCanvasElement !== "function" ||
        threwTypeError(() => HTMLCanvasElement.prototype.toDataURL.call(document.createElement("div"))),
      () => typeof WebGLRenderingContext !== "function" ||
        threwTypeError(() => WebGLRenderingContext.prototype.getParameter.call(null, 0)),
    ];
    return traps.every((t) => safe(t, true)); // a trap that can't run ⇒ pass, never flag
  }, true);

  // Function.prototype.toString Proxy detection — the puppeteer-extra-stealth
  // hallmark. TRUE = BAD (inverted polarity vs the other probes). Two independent
  // tells, each firing only on a confident contradiction:
  //
  // Tell A — shape differential vs a control native. A pristine toString is a
  //   native non-constructor method (no own 'prototype', `new` throws TypeError) —
  //   and so is Function.prototype.call. A Proxy forwards these traits from its
  //   target, so a stealth build whose target is an ORDINARY function makes
  //   toString disagree with the control. Only a DISAGREEMENT fires: an engine
  //   quirk would hit both alike and read as "can't tell".
  //
  // Tell B — error-stack trap frames (CreepJS queryLies-style). Calling a proxied
  //   function routes through the attacker's JS `apply` trap, so when the native
  //   under it throws (guaranteed here by an illegal `this`), the trap's frame
  //   lands in err.stack ("at Function.apply" / "at Object.apply" in V8, "apply@…"
  //   in Gecko/WebKit). A pristine engine throws straight at our call site — a
  //   `.call` invocation never produces an `apply` frame. Message text is never
  //   asserted; an unreadable or empty stack is "can't tell" ⇒ false.
  const nativeToStringProxied = () => safe(() => {
    const fts = Function.prototype.toString;
    const ctrl = Function.prototype.call; // known-native control, same spec shape
    if (typeof fts !== "function" || typeof ctrl !== "function") return false;

    // Tell A
    const constructable = (fn) => !threwTypeError(() => new fn());
    if (constructable(fts) !== constructable(ctrl)) return true;
    if (hasOwn(fts, "prototype") !== hasOwn(ctrl, "prototype")) return true;

    // Tell B
    const stack = safe(() => {
      try { Function.prototype.toString.call(null); return ""; } catch (e) { return String((e && e.stack) || ""); }
    }, "");
    const frames = stack.split("\n").slice(1).join("\n"); // drop the message line
    return /at\s+\S*apply\b|\bapply@/.test(frames);
  }, false); // any failure ⇒ false: never flag on doubt

  // ── v3 probes (G09/G10/G17/G22/G23) ─────────────────────────────────────────
  // Same conventions as the G04 probes: OK bools fail to pass (false only on a
  // confirmed anomaly), TRUE=BAD values default to false on any probe failure,
  // and strings/lists come out empty when a probe can't run — Go treats empty as
  // "not supplied", never evidence.

  // navProtoDescriptorsOK (G17): per WebIDL, webdriver / plugins / languages are
  // accessor (getter-only) properties — enumerable, configurable, living on
  // Navigator.prototype, never own data properties on the navigator instance —
  // and their getters are native. A spoof installed via defineProperty/assignment
  // breaks at least one of those. Only confident anomalies count: an absent or
  // unreadable property (old engine, blocked API) resolves to pass.
  const navProtoDescriptorsOK = () => safe(() => {
    if (typeof Navigator === "undefined" || !Navigator.prototype || typeof navigator === "undefined") return true;
    return ["webdriver", "plugins", "languages"].every((prop) => {
      const owner = findOwner(navigator, prop);
      if (!owner) return true; // property absent entirely ⇒ nothing to check
      const d = safe(() => Object.getOwnPropertyDescriptor(owner, prop), null);
      if (!d) return true; // unreadable ⇒ pass, never flag on doubt
      if (owner !== Navigator.prototype) return false; // own instance property ⇒ spoofed
      return typeof d.get === "function" && d.set === undefined &&
        d.enumerable === true && d.configurable === true &&
        safe(() => NATIVE_RE.test(Function.prototype.toString.call(d.get)), false);
    });
  }, true);

  // chromeRuntimeOK (G22): a genuine window.chrome carries chrome.runtime whose
  // sendMessage/connect are native NON-CONSTRUCTOR methods — no own 'prototype',
  // and `new fn()` throws a TypeError. A stealth-bolted fake (a plain or bound
  // function) carries a prototype or constructs silently; an exotic throw isn't a
  // TypeError (CreepJS hasBadChromeRuntime). Fail-to-pass: absent chrome/runtime
  // is no confident contradiction — absence is no_chrome_object's territory.
  const chromeRuntimeOK = () => safe(() => {
    if (!("chrome" in window)) return true;
    const c = window.chrome;
    if (!c || typeof c !== "object" || !("runtime" in c)) return true;
    const rt = c.runtime;
    if (!rt || typeof rt !== "object") return true;
    for (const name of ["sendMessage", "connect"]) {
      const fn = rt[name];
      if (typeof fn !== "function") continue; // no confident contradiction
      if ("prototype" in fn) return false; // a native method carries none
      try {
        new fn();
        return false; // constructed silently ⇒ a JS stand-in
      } catch (e) {
        if (!(e instanceof TypeError)) return false;
      }
    }
    return true;
  }, true);

  // chromeLateInjection (G22): genuine Chrome creates window.chrome during page
  // setup, so it sits early among window keys; a stealth patch bolting on a fake
  // chrome object appends it late (CreepJS hasHighChromeIndex — 'chrome' in the
  // last ~50 of both the enumerable keys and the own property names). TRUE = BAD.
  const chromeLateInjection = () => safe(() => {
    if (!("chrome" in window)) return false;
    return Object.keys(window).slice(-50).includes("chrome") &&
      Object.getOwnPropertyNames(window).slice(-50).includes("chrome");
  }, false);

  // jsEngine (G23): the JS engine from the Error-stack format — V8 (Chrome/Edge/
  // Opera) frames look like "    at fn (url:line:col)"; SpiderMonkey (Firefox)
  // stacks use "fn@url:line:col" AND the Error carries the proprietary fileName /
  // lineNumber properties; JavaScriptCore (Safari + every iOS browser) also uses
  // "fn@url:line:col" but has no fileName/lineNumber. "" ⇒ couldn't tell (a
  // blocked/empty stack), which Go treats as no signal.
  const jsEngine = () => safe(() => {
    const e = new Error();
    const stack = String((e && e.stack) || "");
    if (stack.includes(" at ")) return "v8";
    if (typeof e.fileName === "string" && typeof e.lineNumber === "number") return "spidermonkey";
    if (stack.includes("@")) return "jsc";
    return "";
  }, "");

  // webrtcProbe (G09): open an RTCPeerConnection against a public STUN server and
  // harvest ICE candidate IPs for ~1.5s (the same timeout shape as the other
  // async probes). mDNS *.local obfuscation names are skipped — they carry no IP.
  // Go compares only PUBLIC candidates against the connection's egress IP (the
  // VPN/proxy pierce) and applies the private/link-local/address-family
  // exclusions; every failure path here resolves empty, which is never a signal.
  const webrtcProbe = () => new Promise((resolve) => {
    const fallback = [];
    try {
      const RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
      if (typeof RTC === "undefined") { resolve(fallback); return; }
      const ips = new Set();
      const pc = new RTC({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        safe(() => pc.close());
        resolve([...ips]);
      };
      const timer = setTimeout(done, 1500);
      const add = (addr) => {
        if (addr && !String(addr).endsWith(".local")) ips.add(String(addr));
      };
      pc.onicecandidate = (ev) => {
        if (!ev.candidate) { done(); return; } // null candidate ⇒ gathering finished
        safe(() => {
          if (ev.candidate.address) { add(ev.candidate.address); return; }
          // candidate:foundation component transport priority ADDRESS port typ ...
          const parts = String(ev.candidate.candidate || "").split(/\s+/);
          if (parts.length > 4 && parts[0].indexOf("candidate:") === 0) add(parts[4]);
        });
      };
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") done(); };
      safe(() => pc.createDataChannel("x")); // an offer needs media or a data channel
      pc.createOffer()
        .then((o) => pc.setLocalDescription(o))
        .catch(done);
    } catch { resolve(fallback); }
  });

  // imageProbe (G10): a 1×1 data-URI GIF that MUST load in any real browser
  // (sannysoft "Broken Image Dimensions"). naturalWidth == 0 — or an error event
  // — means images are blocked/stripped, a headless tell. TRUE = BAD; a timeout
  // or a setup error reads as "can't tell" ⇒ false.
  const imageProbe = () => new Promise((resolve) => {
    try {
      const img = new Image();
      const timer = setTimeout(() => resolve(false), 1500);
      img.onload = () => { clearTimeout(timer); resolve(img.naturalWidth === 0); };
      img.onerror = () => { clearTimeout(timer); resolve(true); };
      img.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
    } catch { resolve(false); }
  });

  // webglGPU reads the unmasked VENDOR and RENDERER from WEBGL_debug_renderer_info.
  // Go compares the two against each other (vendor/renderer coherence, G07) and the
  // GPU family against the UA-claimed OS (G08). Any failure (no WebGL, extension
  // blocked) yields empty strings, which Go treats as "not supplied", never a tell.
  const webglGPU = () => safe(() => {
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    const ext = gl?.getExtension("WEBGL_debug_renderer_info");
    return {
      webglVendor: ext ? (gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || "") : "",
      webglRenderer: ext ? (gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "") : "",
    };
  }, { webglVendor: "", webglRenderer: "" });

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
    const count = () => {
      const baseW = Object.fromEntries(bases.map((b) => [b, w(b)]));
      return probes.filter((p) => bases.some((b) => w(`'${p}',${b}`) !== baseW[b])).length;
    };
    // The first canvas text measurement after navigation can hit a cold font cache
    // and return the generic width for every probe — a spurious "no fonts". Warm the
    // cache with a throwaway pass, then take the real measurement.
    count();
    return count();
  }, -1);

  // iframeProxied — CreepJS hasIframeProxy. The puppeteer-extra-stealth
  // iframe.contentWindow patch installs a getter that THROWS when a fresh srcdoc
  // frame's window is read this early; a genuine engine never throws here (Chrome
  // returns the WindowProxy even detached, Firefox returns null). TRUE = BAD; any
  // setup failure reads as false (never flag on doubt).
  const iframeProxied = () => {
    try {
      const f = document.createElement("iframe");
      f.srcdoc = "botcheck";
      void f.contentWindow; // the stealth getter throws here; a real engine doesn't
      return false;
    } catch { return true; }
  };

  // iframeProbe re-reads navigator inside a display:none iframe (a second JS
  // context). Anti-detect tools commonly spoof only the top frame's navigator, so
  // any value the iframe reports differently is a consistency tell — including
  // navigator.webdriver, which stealth patches fix in the top frame but forget in
  // the fresh iframe realm (G11). Empty values mean the read failed — never a signal.
  const iframeProbe = () => safe(() => {
    const f = document.createElement("iframe");
    f.style.display = "none";
    document.body.appendChild(f);
    const n = f.contentWindow.navigator;
    const out = {
      ua: n.userAgent || "",
      languages: [...(n.languages || [])],
      cores: n.hardwareConcurrency || 0,
      platform: (n.userAgentData && n.userAgentData.platform) || "",
      webdriver: n.webdriver === true,
      proxied: iframeProxied(),
    };
    f.remove();
    return out;
  }, { ua: "", languages: [], cores: 0, platform: "", webdriver: false, proxied: false });

  // workerProbe recomputes the navigator values and runs the CDP trap inside a Web
  // Worker (a third JS context) — a top-frame-only spoof leaks here. It also tries
  // an OffscreenCanvas WebGL unmasked-renderer read (the CreepJS hasBadWebGL diff);
  // many browsers lack OffscreenCanvas WebGL, and that just yields "". Uses a blob
  // URL so no separate file is needed; resolves with a fallback on timeout/error.
  const workerProbe = () => new Promise((resolve) => {
    const fallback = { ua: "", cdp: false, languages: [], cores: 0, platform: "", webgl: "" };
    try {
      const src =
        "self.onmessage=()=>{let c=false;const e=new Error();" +
        "try{Object.defineProperty(e,'stack',{get(){c=true;return 'x';}});}catch(_){}" +
        "try{console.debug(e);}catch(_){}" +
        "let g='';try{const cv=new OffscreenCanvas(1,1);const gl=cv.getContext('webgl');" +
        "const x=gl&&gl.getExtension('WEBGL_debug_renderer_info');" +
        "g=x?(gl.getParameter(x.UNMASKED_RENDERER_WEBGL)||''):'';}catch(_){}" +
        "self.postMessage({ua:navigator.userAgent,cdp:c," +
        "languages:[...(navigator.languages||[])],cores:navigator.hardwareConcurrency||0," +
        "platform:(navigator.userAgentData&&navigator.userAgentData.platform)||'',webgl:g});};";
      const url = URL.createObjectURL(new Blob([src], { type: "application/javascript" }));
      const w = new Worker(url);
      const done = (v) => { clearTimeout(timer); safe(() => w.terminate()); URL.revokeObjectURL(url); resolve(v); };
      const timer = setTimeout(() => done(fallback), 800);
      w.onmessage = (ev) => done(ev.data || fallback);
      w.onerror = () => done(fallback);
      w.postMessage("go");
    } catch { resolve(fallback); }
  });

  // swProbe asks the Service Worker at /botcheck-sw.js (served by the app itself —
  // a blob: URL can't be registered as a SW) for its navigator values: a fourth JS
  // context to cross-check. The SW answers over a MessageChannel port so we don't
  // race a global message listener; it is unregistered afterward so nothing is left
  // behind on the visitor's browser. Every failure path resolves with empty values
  // (no SW support, slow first install, HTTPS-only restrictions) — never a signal.
  const swProbe = () => new Promise((resolve) => {
    const fallback = { ua: "", languages: [], cores: 0, platform: "", webdriver: false, cdp: false };
    try {
      if (!("serviceWorker" in navigator)) { resolve(fallback); return; }
      let reg = null;
      let settled = false;
      // Never leave a SW behind on the visitor's browser.
      const cleanup = () => safe(() => { const p = reg && reg.unregister(); if (p) p.catch(() => {}); });
      const done = (v) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        cleanup();
        resolve(v);
      };
      const timer = setTimeout(() => done(fallback), 800);
      const channel = new MessageChannel();
      channel.port1.onmessage = (ev) => done(ev.data || fallback);
      navigator.serviceWorker.register("/botcheck-sw.js")
        // register() resolves before activation; ready waits for an active worker.
        .then((r) => {
          reg = r;
          if (settled) { cleanup(); return; } // timed out while the SW script loaded
          return navigator.serviceWorker.ready;
        })
        .then((active) => active && active.active && active.active.postMessage("go", [channel.port2]))
        .catch(() => done(fallback));
    } catch { resolve(fallback); }
  });

  const uaData = async () => {
    const d = navigator.userAgentData;
    // fullVersionList is the load-bearing G01 signal: a UA-string spoof that edits
    // "Chrome/NNN" but leaves userAgentData intact disagrees with the "Chromium"
    // brand entry Go compares against. platform is low-entropy (read directly);
    // fullVersionList is high-entropy, so it needs getHighEntropyValues — which can
    // REJECT (e.g. NotAllowedError in a sandbox), and safe() only catches synchronous
    // throws, so the `.catch` stops a rejection from aborting the whole fingerprint.
    const hi = await safe(() => d?.getHighEntropyValues?.(["fullVersionList"])?.catch(() => null), null);
    return {
      platform: safe(() => d?.platform ?? "", ""),
      fullVersionList: hi?.fullVersionList ?? [],
    };
  };

  // engineFamily feature-detects the real rendering engine, independent of the
  // (spoofable) UA string: gecko (Firefox), webkit (Safari + all iOS browsers),
  // blink (Chrome/Edge/Opera/Chromium). Each probe reads a capability unique to one
  // engine; Go compares the result to the engine the UA claims. "" ⇒ couldn't tell.
  const engineFamily = () => safe(() => {
    const sup = (p, v) => safe(() => CSS.supports(p, v), false);
    if (sup("-moz-appearance", "none") || "MozAppearance" in document.documentElement.style) return "gecko";
    if (typeof window.GestureEvent !== "undefined") return "webkit";
    if (sup("-webkit-app-region", "drag") || "webkitRequestFileSystem" in window) return "blink";
    return "";
  }, "");

  const permState = () => safe(
    () => navigator.permissions.query({ name: "notifications" }).then((p) => p.state || "", () => ""),
    Promise.resolve(""),
  );

  const collect = async () => {
    const iframe = iframeProbe();
    const [worker, sw, ua, perm, webrtcIPs, imageBroken] = await Promise.all(
      [workerProbe(), swProbe(), uaData(), permState(), webrtcProbe(), imageProbe()],
    );
    return {
      // Payload version. Bump when a new field is damning-when-false (a missing
      // key binds false server-side): Go skips those rules on older payloads, so
      // a stale cached copy of this file never reads as tampered. v2 = G04 probes;
      // v3 = the G09–G14/G17/G22/G23 batch + Layer-1 backlog fields.
      v: 3,
      webdriver: safe(() => navigator.webdriver === true, false),
      frameworkGlobals: frameworkGlobals(),
      cdpMainThread: cdpTrap(),
      cdpWorker: !!worker.cdp,
      nativeToStringOK: nativeToStringOK(),
      nativeDescriptorsOK: nativeDescriptorsOK(), // G04 deep probes — same fail-to-pass
      nativeCallNewOK: nativeCallNewOK(), // convention: false only on a confirmed tamper
      nativeToStringProxied: nativeToStringProxied(), // inverted: true = toString is a Proxy
      navMainUA: safe(() => navigator.userAgent, ""),
      navWorkerUA: worker.ua || "",
      navIframeUA: iframe.ua || "",
      languages: safe(() => [...(navigator.languages || [])], []),
      permissionState: perm,
      notificationPermission: safe(() => (typeof Notification !== "undefined" ? Notification.permission : ""), ""),
      hasChromeObject: safe(() => !!window.chrome, false),
      ...webglGPU(),
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
      productSub: safe(() => navigator.productSub ?? "", ""),
      engine: engineFamily(),
      // G03: the same navigator values re-read in the other JS contexts. A
      // top-frame-only spoof leaves these untouched, so Go diffs each against the
      // main thread's claim. Empty/0 ⇒ the context didn't answer — never a signal.
      swUA: sw.ua || "",
      workerLanguages: worker.languages || [],
      iframeLanguages: iframe.languages || [],
      swLanguages: sw.languages || [],
      workerCores: worker.cores || 0,
      iframeCores: iframe.cores || 0,
      swCores: sw.cores || 0,
      workerPlatform: worker.platform || "",
      iframePlatform: iframe.platform || "",
      swPlatform: sw.platform || "",
      workerWebGLRenderer: worker.webgl || "",
      ...canvasProbe(),
      ...codecs(),
      // v3 batch: the G09–G14/G17/G22/G23 signals + the Layer-1 backlog fields.
      // The OK bools fail to pass (gated on v server-side); the TRUE=BAD booleans
      // and the value fields default safe on a stale payload.
      iframeWebdriver: iframe.webdriver === true, // G11: webdriver re-read in the iframe
      iframeProxied: iframe.proxied === true, // G11: iframe contentWindow Proxy (true = bad)
      swWebdriver: sw.webdriver === true, // G14: webdriver in the Service Worker
      swCDP: !!sw.cdp, // G14: the CDP Error.stack trap, in the Service Worker
      maxTouchPoints: safe(() => navigator.maxTouchPoints ?? 0, 0), // G12
      navProtoDescriptorsOK: navProtoDescriptorsOK(), // G17 fail-to-pass
      chromeRuntimeOK: chromeRuntimeOK(), // G22 fail-to-pass
      chromeLateInjection: chromeLateInjection(), // G22: true = bad
      jsEngine: jsEngine(), // G23: "v8" | "spidermonkey" | "jsc" | ""
      webrtcIPs: webrtcIPs, // G09: deduped candidate IPs (mDNS skipped); [] = no signal
      imageBroken: imageBroken, // G10: true = bad
      mimeTypes: safe(() => navigator.mimeTypes?.length ?? 0, 0),
      outerH: safe(() => window.outerHeight ?? 0, 0),
      innerH: safe(() => window.innerHeight ?? 0, 0),
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

  // Auto-run once the page is warmed up. Probes that touch the font cache and media
  // pipeline can read "cold" at DOMContentLoaded — a spurious "no fonts / no codecs"
  // — and a proxy extension that slows the load makes that far more likely. Wait for
  // the load event and document.fonts.ready so those reads are stable, with a
  // timeout fallback so a stalled resource never leaves the page on "analyzing".
  let autoStarted = false;
  const autoRun = () => {
    if (autoStarted) return;
    autoStarted = true;
    const fontsReady = (document.fonts && document.fonts.ready) || Promise.resolve();
    fontsReady.catch(() => {}).then(() => runBotCheck());
  };
  if (document.readyState === "complete") {
    autoRun();
  } else {
    window.addEventListener("load", autoRun);
    setTimeout(autoRun, 4000);
  }
})();
