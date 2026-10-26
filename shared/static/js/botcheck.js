// botcheck collector: POSTs client-only signals to /check; probes run in safe(), scoring stays in Go.
(() => {
  "use strict";

  const NATIVE_RE = /\{\s*\[native code\]\s*\}/;

  // Automation-only globals. CEF/CefSharp stay out: desktop apps embed them (UA embedded_runtime rule).
  const WINDOW_MARKERS = [
    "__playwright", "__pw_manual", "__PW_inspect", "_playwright",
    "__pwInitScripts", "__playwright__binding__", // Playwright binding hooks
    "__nightmare", "_phantom", "callPhantom", "phantom", "__phantomas",
    "domAutomation", "domAutomationController", "_Selenium_IDE_Recorder",
    "__selenium_unwrapped", "__webdriver_evaluate", "__driver_evaluate",
    "__webdriver_script_fn", "__$webdriverAsyncExecutor", "__lastWatirAlert",
    "__fxdriver_unwrapped", "webdriver",
    // G13: wider Selenium/Watir canon (intoli/fp-scanner lineage) that BrowserScan/sannysoft check.
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

  // A CDP client with Runtime.enable (or open DevTools) serializes the logged Error and reads .stack,
  // firing the getter; a plain browser never does. Never read .stack here, or it self-triggers.
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
    // Sweep own names too: ChromeDriver's cdc_ key has a random suffix no list can name (G17).
    for (const obj of [document, window]) {
      safe(() => Object.getOwnPropertyNames(obj).forEach((n) => {
        if (SUSPECT_RE.test(n) && !found.includes(n)) found.push(n);
      }));
    }
    // Sequentum's scraping runtime brands window.external (fp-scanner's SEQUENTUM check).
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

  // ── G04 lie detection: stealth kits fake toString, so probe what a lie can't hide; can't run = pass ──

  // Fails to "absent", the conservative answer for every use below.
  const hasOwn = (o, k) => safe(() => Object.hasOwn(o, k), false);

  // Read descriptors where the prop lives: a patch may install an own property on the instance.
  const findOwner = (obj, prop) => {
    let o = obj;
    while (o && !Object.prototype.hasOwnProperty.call(o, prop)) o = Object.getPrototypeOf(o);
    return o;
  };

  // Only the TypeError class is asserted: messages are engine-specific.
  const threwTypeError = (fn) => {
    try { fn(); return false; } catch (e) { return e instanceof TypeError; }
  };

  // A patch breaks a native's descriptor or own props. Enumerability differs BY SPEC: ECMA-262
  // built-ins are non-enumerable, WebIDL ops enumerable; asserting the wrong one flags every browser.
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
      if (!obj) return true;
      const owner = findOwner(obj, prop);
      const d = owner && safe(() => Object.getOwnPropertyDescriptor(owner, prop), null);
      if (!d) return true;
      checked++;
      if (typeof d.value !== "function") return false; // turned into getter/data lie
      return d.writable === true && d.enumerable === enumerable && d.configurable === true &&
        d.value.name === name && d.value.length === len &&
        !hasOwn(d.value, "prototype") && !hasOwn(d.value, "arguments") && !hasOwn(d.value, "caller");
    });
    return checked > 0 && ok;
  }, true);

  // Platform natives reject wrong calls in ways a plain-function patch almost never reproduces.
  const nativeCallNewOK = () => safe(() => {
    const traps = [
      // WebIDL operation is not constructor: `new query()` must throw.
      () => typeof navigator === "undefined" || !navigator.permissions ||
        threwTypeError(() => new (navigator.permissions.query)()),
      // A platform constructor called WITHOUT new must throw ("Illegal constructor"); shims forget.
      () => typeof HTMLElement !== "function" ||
        threwTypeError(() => HTMLElement()),
      // WebIDL methods brand-check their receiver: a foreign `this` must throw ("Illegal invocation").
      () => typeof HTMLCanvasElement !== "function" ||
        threwTypeError(() => HTMLCanvasElement.prototype.toDataURL.call(document.createElement("div"))),
      () => typeof WebGLRenderingContext !== "function" ||
        threwTypeError(() => WebGLRenderingContext.prototype.getParameter.call(null, 0)),
    ];
    return traps.every((t) => safe(t, true));
  }, true);

  // Proxy around Function.prototype.toString (puppeteer-extra-stealth hallmark). TRUE = BAD.
  // Older V8 names a trap frame "at Object.apply", current V8 an alias ("[as apply]"): match both.
  const TRAP_ALIAS_RE =
    /\[as (?:apply|construct|get|set|has|deleteProperty|defineProperty|getOwnPropertyDescriptor|ownKeys|getPrototypeOf|setPrototypeOf|isExtensible|preventExtensions)\]/;
  const nativeToStringProxied = () => safe(() => {
    const fts = Function.prototype.toString;
    const ctrl = Function.prototype.call; // known-native control, same spec shape
    if (typeof fts !== "function" || typeof ctrl !== "function") return false;

    // A: a Proxy forwards its target's shape, so an ordinary-function target disagrees with .call.
    const constructable = (fn) => !threwTypeError(() => new fn());
    if (constructable(fts) !== constructable(ctrl)) return true;
    if (hasOwn(fts, "prototype") !== hasOwn(ctrl, "prototype")) return true;

    // B: when the native under a proxied call throws, the trap's own frame lands in the stack.
    const stack = safe(() => {
      try { Function.prototype.toString.call(null); return ""; } catch (e) { return String((e && e.stack) || ""); }
    }, "");
    const frames = stack.split("\n").slice(1).join("\n"); // drop the message line
    return /at\s+\S*apply\b|\bapply@/.test(frames) || TRAP_ALIAS_RE.test(frames);
  }, false);

  // ── v3 probes (G09/G10/G17/G22/G23): empty values are "not supplied" to Go, never evidence ──

  // Per WebIDL, webdriver/plugins/languages are native getters on Navigator.prototype (G17).
  const navProtoDescriptorsOK = () => safe(() => {
    if (typeof Navigator === "undefined" || !Navigator.prototype || typeof navigator === "undefined") return true;
    return ["webdriver", "plugins", "languages"].every((prop) => {
      const owner = findOwner(navigator, prop);
      if (!owner) return true;
      const d = safe(() => Object.getOwnPropertyDescriptor(owner, prop), null);
      if (!d) return true;
      if (owner !== Navigator.prototype) return false; // own instance property ⇒ spoofed
      return typeof d.get === "function" && d.set === undefined &&
        d.enumerable === true && d.configurable === true &&
        safe(() => NATIVE_RE.test(Function.prototype.toString.call(d.get)), false);
    });
  }, true);

  // G22: runtime.sendMessage/connect must be native non-constructors; Chrome for Testing has no runtime: pass.
  const chromeRuntimeOK = () => safe(() => {
    if (!("chrome" in window)) return true;
    const c = window.chrome;
    if (!c || typeof c !== "object" || !("runtime" in c)) return true;
    const rt = c.runtime;
    if (!rt || typeof rt !== "object") return true;
    for (const name of ["sendMessage", "connect"]) {
      const fn = rt[name];
      if (typeof fn !== "function") continue;
      if ("prototype" in fn) return false; // native method carries none
      try {
        new fn();
        return false; // constructed silently ⇒ JS stand-in
      } catch (e) {
        if (!(e instanceof TypeError)) return false;
      }
    }
    return true;
  }, true);

  // A bolted-on window.chrome lands among the last window keys (CreepJS hasHighChromeIndex). TRUE = BAD.
  const chromeLateInjection = () => safe(() => {
    if (!("chrome" in window)) return false;
    return Object.keys(window).slice(-50).includes("chrome") &&
      Object.getOwnPropertyNames(window).slice(-50).includes("chrome");
  }, false);

  // V8 stacks use " at "; SpiderMonkey and JSC "fn@url", but only SpiderMonkey has Error.fileName (G23).
  const jsEngine = () => safe(() => {
    const e = new Error();
    const stack = String((e && e.stack) || "");
    if (stack.includes(" at ")) return "v8";
    if (typeof e.fileName === "string" && typeof e.lineNumber === "number") return "spidermonkey";
    if (stack.includes("@")) return "jsc";
    return "";
  }, "");

  // ICE candidate IPs via a public STUN server (G09); mDNS *.local names carry no IP. Go filters the rest.
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
      safe(() => pc.createDataChannel("x")); // offer needs media or data channel
      pc.createOffer()
        .then((o) => pc.setLocalDescription(o))
        .catch(done);
    } catch { resolve(fallback); }
  });

  // A data-URI GIF loads in any real browser (sannysoft "Broken Image Dimensions", G10). TRUE = BAD.
  const imageProbe = () => new Promise((resolve) => {
    try {
      const img = new Image();
      const timer = setTimeout(() => resolve(false), 1500);
      img.onload = () => { clearTimeout(timer); resolve(img.naturalWidth === 0); };
      img.onerror = () => { clearTimeout(timer); resolve(true); };
      img.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
    } catch { resolve(false); }
  });

  // ── v4 "env" probes (G15/G21): fail to ABSENT; only matchmedia_missing and netinfo_incoherent score ──

  // matchMedia exists in every real browser, so its absence on a browser UA is a tell (G15).
  const mediaProbe = () => {
    const hasMM = safe(() => typeof window.matchMedia === "function", false);
    const out = { matchMedia: hasMM };
    if (!hasMM) return out;
    const mq = (q) => safe(() => window.matchMedia(q).matches, null); // null = query failed
    if (mq("(prefers-color-scheme: dark)") === true) out.colorScheme = "dark";
    else if (mq("(prefers-color-scheme: light)") === true) out.colorScheme = "light";
    const fc = mq("(forced-colors: active)");
    if (fc !== null) out.forcedColors = fc;
    const rm = mq("(prefers-reduced-motion: reduce)");
    if (rm !== null) out.reducedMotion = rm;
    const dr = mq("(dynamic-range: high)");
    if (dr !== null) out.dynamicRange = dr ? "high" : "standard";
    // Widest gamut wins; srgb is universal, so it's the answer whenever the query API works.
    if (mq("(color-gamut: rec2020)") === true) out.gamut = "rec2020";
    else if (mq("(color-gamut: p3)") === true) out.gamut = "p3";
    else if (mq("(color-gamut: srgb)") !== null) out.gamut = "srgb";
    const dpr = safe(() => window.devicePixelRatio, 0);
    if (typeof dpr === "number" && isFinite(dpr) && dpr > 0) out.dpr = dpr;
    return out;
  };

  // navigator.connection is missing on most Firefox/Safari, so null is normal: "not supplied" (G21).
  const connectionProbe = () => safe(() => {
    const c = navigator.connection;
    if (!c) return null;
    const out = {};
    if (typeof c.effectiveType === "string" && c.effectiveType) out.effectiveType = c.effectiveType;
    if (typeof c.downlink === "number" && isFinite(c.downlink)) out.downlink = c.downlink;
    if (typeof c.rtt === "number" && isFinite(c.rtt)) out.rtt = c.rtt;
    if (typeof c.saveData === "boolean") out.saveData = c.saveData;
    return out;
  }, null);

  // Quota in MB, 0 = couldn't tell; raw dump only, no incognito heuristic (G19 was skipped).
  const storageProbe = () => safe(
    () => navigator.storage?.estimate?.().then((e) => {
      const q = e && e.quota;
      return typeof q === "number" && isFinite(q) && q > 0 ? Math.round(q / 1048576) : 0;
    }, () => 0),
    Promise.resolve(0),
  );

  // Each name fails to absent (older Safari rejects 'geolocation'); user choices, so never scored.
  const permissionsProbe = () => {
    if (!safe(() => !!(navigator.permissions && navigator.permissions.query), false)) {
      return Promise.resolve(null);
    }
    const q = (name) => safe(
      () => navigator.permissions.query({ name }).then((p) => p.state || "", () => ""),
      Promise.resolve(""),
    );
    return Promise.all([q("notifications"), q("geolocation")]).then(([n, g]) => {
      const out = {};
      if (n) out.notifications = n;
      if (g) out.geolocation = g;
      return out;
    });
  };

  // ClearKey EME (G21): true/false are answers; null = couldn't run, never evidence.
  const emeProbe = () => safe(
    () => {
      if (typeof navigator.requestMediaKeySystemAccess !== "function") return Promise.resolve(null);
      const cfg = [{
        initDataTypes: ["cenc"],
        videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }],
      }];
      return navigator.requestMediaKeySystemAccess("org.w3.clearkey", cfg).then(
        () => true,
        (err) => (err && err.name === "NotSupportedError" ? false : null),
      );
    },
    Promise.resolve(null),
  );

  // globalPrivacyControl (G21): a boolean where exposed (Firefox), else null, never false.
  const gpcProbe = () => safe(() => {
    const g = navigator.globalPrivacyControl;
    return typeof g === "boolean" ? g : null;
  }, null);

  // quota/perms/eme come from collect()'s single Promise.all, so they add no wall time.
  const envSection = (quotaMB, perms, eme) => {
    const env = mediaProbe();
    const conn = connectionProbe();
    if (conn) env.connection = conn;
    if (quotaMB > 0) env.storageQuotaMB = quotaMB;
    const gpc = gpcProbe();
    if (gpc !== null) env.gpc = gpc;
    if (perms) env.permissions = perms;
    if (eme !== null) env.emeClearKey = eme;
    return env;
  };

  // Go checks vendor vs renderer (G07) and GPU family vs the UA's OS (G08); "" = not supplied.
  const webglGPU = () => safe(() => {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl2") || c.getContext("webgl") || c.getContext("experimental-webgl");
    if (!gl) return { webglVendor: "disabled", webglRenderer: "software (WebGL unavailable)" };
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    const v = (ext && gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)) || gl.getParameter(gl.VENDOR) || "";
    const r = (ext && gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) || gl.getParameter(gl.RENDERER) || "";
    return {
      webglVendor: v,
      webglRenderer: r,
    };
  }, { webglVendor: "", webglRenderer: "" });

  // Draws twice: unequal hashes = anti-fingerprint noise; all-transparent = blocked or headless.
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
  }), { codecH264: true, codecAAC: true }); // default true ⇒ probe failure never flags

  // Counts probe fonts whose width differs from the generic baselines; -1 = couldn't measure.
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
    // A cold font cache makes the first pass report no fonts: warm it with a throwaway one.
    count();
    return count();
  }, -1);

  // Stealth's contentWindow getter throws on a fresh srcdoc frame; real engines don't. TRUE = BAD.
  const iframeProxied = () => {
    try {
      const f = document.createElement("iframe");
      f.srcdoc = "botcheck";
      void f.contentWindow;
      return false;
    } catch { return true; }
  };

  // Second JS context: anti-detect tools often spoof only the top frame, webdriver included (G11).
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

  // Third JS context; also reads the OffscreenCanvas WebGL renderer (CreepJS hasBadWebGL diff).
  const workerProbe = () => new Promise((resolve) => {
    const fallback = { ua: "", cdp: false, languages: [], cores: 0, platform: "", webgl: "" };
    try {
      const src =
        "self.onmessage=()=>{let c=false;const e=new Error();" +
        "try{Object.defineProperty(e,'stack',{get(){c=true;return 'x';}});}catch(_){}" +
        "try{console.debug(e);}catch(_){}" +
        "let g='';try{const cv=new OffscreenCanvas(1,1);const gl=cv.getContext('webgl2')||cv.getContext('webgl');" +
        "if(gl){const x=gl.getExtension('WEBGL_debug_renderer_info');" +
        "g=(x&&gl.getParameter(x.UNMASKED_RENDERER_WEBGL))||gl.getParameter(gl.RENDERER)||'';}" +
        "else{g='software (WebGL unavailable)';}}catch(_){}" +
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

  // Fourth JS context (a blob: URL can't be a SW); a MessageChannel reply can't race the global listener.
  const swProbe = () => new Promise((resolve) => {
    const fallback = { ua: "", languages: [], cores: 0, platform: "", webdriver: false, cdp: false };
    try {
      if (!("serviceWorker" in navigator)) { resolve(fallback); return; }
      let reg = null;
      let settled = false;
      // Never leave SW behind on visitor's browser.
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
        // register() resolves before activation; ready waits for active worker.
        .then((r) => {
          reg = r;
          if (settled) { cleanup(); return; } // timed out while SW script loaded
          return navigator.serviceWorker.ready;
        })
        .then((active) => active && active.active && active.active.postMessage("go", [channel.port2]))
        .catch(() => done(fallback));
    } catch { resolve(fallback); }
  });

  const uaData = async () => {
    const d = navigator.userAgentData;
    // fullVersionList (G01) can reject async (NotAllowedError in a sandbox), which safe() can't catch.
    const hi = await safe(() => d?.getHighEntropyValues?.(["fullVersionList"])?.catch(() => null), null);
    return {
      platform: safe(() => d?.platform ?? "", ""),
      fullVersionList: hi?.fullVersionList ?? [],
    };
  };

  // Feature-detects the real engine, independent of the spoofable UA; "" = couldn't tell.
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
    const [worker, sw, ua, perm, webrtcIPs, imageBroken, quotaMB, perms, eme] = await Promise.all(
      [workerProbe(), swProbe(), uaData(), permState(), webrtcProbe(), imageProbe(),
        storageProbe(), permissionsProbe(), emeProbe()],
    );
    return {
      // Bump when adding a damning-when-false field: Go skips its rules on older v, so stale cached copies pass.
      v: 4,
      webdriver: safe(() => navigator.webdriver === true, false),
      frameworkGlobals: frameworkGlobals(),
      cdpMainThread: cdpTrap(),
      cdpWorker: !!worker.cdp,
      nativeToStringOK: nativeToStringOK(),
      nativeDescriptorsOK: nativeDescriptorsOK(), // G04: false only on confirmed tamper
      nativeCallNewOK: nativeCallNewOK(),
      nativeToStringProxied: nativeToStringProxied(), // inverted: true = toString is Proxy
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
      // G03: the same values from other JS contexts; empty/0 = the context didn't answer, never a signal.
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
      // v3 batch: OK bools fail to pass (gated on v server-side); TRUE=BAD fields default safe.
      iframeWebdriver: iframe.webdriver === true,
      iframeProxied: iframe.proxied === true, // G11: iframe contentWindow Proxy (true = bad)
      swWebdriver: sw.webdriver === true,
      swCDP: !!sw.cdp, // G14: CDP Error.stack trap, in Service Worker
      maxTouchPoints: safe(() => navigator.maxTouchPoints ?? 0, 0),
      navProtoDescriptorsOK: navProtoDescriptorsOK(),
      chromeRuntimeOK: chromeRuntimeOK(),
      chromeLateInjection: chromeLateInjection(), // G22: true = bad
      jsEngine: jsEngine(), // G23: "v8" | "spidermonkey" | "jsc" | ""
      webrtcIPs: webrtcIPs, // G09: deduped candidate IPs (mDNS skipped); [] = no signal
      imageBroken: imageBroken, // G10: true = bad
      mimeTypes: safe(() => navigator.mimeTypes?.length ?? 0, 0),
      outerH: safe(() => window.outerHeight ?? 0, 0),
      innerH: safe(() => window.innerHeight ?? 0, 0),
      env: envSection(quotaMB, perms, eme),
    };
  };

  // ── G46: localStorage-only history; private mode can make any access throw, so all is safe() ──
  const HISTORY_KEY = "botcheck:history";
  const HISTORY_MAX = 20;
  const VERDICT_CLASS = { human: "text-ok", suspicious: "text-warn-ink", "good-bot": "text-brand-ink" };

  const readHistory = () => safe(() => {
    const list = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(list) ? list : [];
  }, []);

  const renderHistory = () => safe(() => {
    const card = document.getElementById("botcheck-history");
    const ul = card && card.querySelector("ul");
    if (!ul) return;
    const entries = readHistory();
    card.hidden = entries.length === 0;
    ul.replaceChildren(...entries.reverse().map((e) => {
      const li = document.createElement("li");
      li.className = "flex items-baseline gap-3 py-2";
      const time = document.createElement("span");
      time.className = "flex-1 min-w-0 text-faint";
      time.textContent = new Date(e.ts).toLocaleString();
      const score = document.createElement("span");
      score.className = "shrink-0 font-mono text-strong";
      score.textContent = e.score + "/100";
      const verdict = document.createElement("span");
      verdict.className = "shrink-0 font-mono text-xs " + (VERDICT_CLASS[e.verdict] || "text-danger");
      verdict.textContent = e.verdict;
      li.append(time, score, verdict);
      return li;
    }));
  });

  const recordHistory = () => safe(() => {
    const el = document.querySelector("#result [data-score][data-verdict]");
    const score = el ? Number(el.getAttribute("data-score")) : NaN;
    if (!Number.isFinite(score)) return; // error fragment carries no verdict card
    const list = readHistory();
    list.push({ ts: Date.now(), score, verdict: el.getAttribute("data-verdict") || "" });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(-HISTORY_MAX)));
    renderHistory();
  });

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
      if (result) {
        result.innerHTML = await res.text();
        if (window.Alpine) window.Alpine.initTree(result);
      }
      recordHistory();
      if (status) status.textContent = "";
    } catch {
      if (status) status.textContent = "check failed — try again";
    }
  };

  window.runBotCheck = runBotCheck;
  renderHistory(); // G46: a returning visitor sees their history before the first run

  // Font/media probes read empty before load and fonts.ready; a timeout stops a stall hanging "analyzing".
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
