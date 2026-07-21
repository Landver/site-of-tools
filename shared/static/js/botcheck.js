// botcheck collector — vendored, hand-written, no npm (CLAUDE.md rule #3).
//
// Gathers client-side signals server can't see: navigator/webdriver/CDP
// traces, WebGL GPU vendor+renderer, cross-context navigator values from Web
// Worker/iframe/Service Worker, permissions, geometry, timezone, userAgentData
// version list, feature-detected engine family, engine constants like
// navigator.productSub, + v4 "env" probes (media queries, connection/storage/
// EME/GPC surface). POSTs as JSON to /check → swaps returned HTML fragment
// into #result. After run, appends verdict to localStorage-only history (G46,
// never uploaded). Every probe wrapped in safe() → one failure never aborts
// collection. Scoring/verdict happens server-side in Go — this only
// collects, never decides.
(() => {
  "use strict";

  const NATIVE_RE = /\{\s*\[native code\]\s*\}/;

  // Known automation-framework globals; presence of any = near-standalone tell.
  // Only AUTOMATION-only markers belong here — embedded-runtime markers
  // (CefSharp/Awesomium/CEF) deliberately excluded: legit desktop apps embed
  // those engines, UA-side embedded_runtime rule already covers that class.
  const WINDOW_MARKERS = [
    "__playwright", "__pw_manual", "__PW_inspect", "_playwright",
    "__pwInitScripts", "__playwright__binding__", // Playwright binding hooks
    "__nightmare", "_phantom", "callPhantom", "phantom", "__phantomas",
    "domAutomation", "domAutomationController", "_Selenium_IDE_Recorder",
    "__selenium_unwrapped", "__webdriver_evaluate", "__driver_evaluate",
    "__webdriver_script_fn", "__$webdriverAsyncExecutor", "__lastWatirAlert",
    "__fxdriver_unwrapped", "webdriver",
    // G13: wider Selenium/Watir canon from intoli/fp-scanner lineage that
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

  // cdpTrap: define getter on Error's `stack`, hand Error to console. DevTools-
  // Protocol client w/ Runtime.enable (Puppeteer/Playwright/Selenium 4) — or open
  // DevTools panel — serializes object, reads `.stack`, firing getter; plain
  // browser never reads it. Must NOT touch `.stack` ourselves, or we'd self-trigger.
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
    // Sweep for ChromeDriver's random-suffixed cdc_ key + similar markers — over
    // both document and window own property names (G17): injected automation
    // global explicit lists miss still surfaces here.
    for (const obj of [document, window]) {
      safe(() => Object.getOwnPropertyNames(obj).forEach((n) => {
        if (SUSPECT_RE.test(n) && !found.includes(n)) found.push(n);
      }));
    }
    // Sequentum's scraping runtime brands window.external (fp-scanner's SEQUENTUM
    // check; deviceandbrowserinfo's isSequentum reads same string).
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
  // Shallow nativeToStringOK() above only regexes toString output; stealth
  // toolkits (puppeteer-extra-stealth) defeat exactly that by swapping
  // Function.prototype.toString for Proxy that lies about patched functions.
  // These probes look for what lie can't hide: impossible property descriptors,
  // missing call/new TypeError traps, Proxy artifacts. Same convention as
  // codecs(): probe that can't run or throws yields PASS value — never flag
  // on doubt.

  // hasOwn = Object.hasOwn w/ fail-safe: can't run (very old engine) →
  // "absent" is conservative answer for every use below.
  const hasOwn = (o, k) => safe(() => Object.hasOwn(o, k), false);

  // findOwner walks prototype chain to object that actually owns prop —
  // descriptor must be read where property lives, not assumed to sit on
  // expected prototype (patch may install own property on instance).
  const findOwner = (obj, prop) => {
    let o = obj;
    while (o && !Object.prototype.hasOwnProperty.call(o, prop)) o = Object.getPrototypeOf(o);
    return o;
  };

  // threwTypeError reports whether fn throws specifically TypeError — ONLY
  // thing traps below assert (messages are engine-specific).
  const threwTypeError = (fn) => {
    try { fn(); return false; } catch (e) { return e instanceof TypeError; }
  };

  // Descriptor / own-property sanity on same natives nativeToStringOK checks.
  // Genuine native method = writable / configurable DATA property on its
  // prototype, carries no own 'prototype' (non-constructors), 'arguments' or
  // 'caller', keeps spec-mandated name/length — monkey-patch (plain or bound
  // function, or defineProperty w/ wrong flags) breaks at least one of these.
  // Enumerability differs BY SPEC, asserted per target: ECMA-262 built-ins
  // (Function.prototype.toString) non-enumerable, WebIDL operations
  // (permissions.query, toDataURL, getParameter) always enumerable — asserting
  // one family's shape on other false-fires every real browser. Absent APIs
  // skipped like nativeToStringOK; any probe failure yields true.
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
      if (!d) return true; // property gone entirely ⇒ skip, same as absent API
      checked++;
      if (typeof d.value !== "function") return false; // turned into getter/data lie
      return d.writable === true && d.enumerable === enumerable && d.configurable === true &&
        d.value.name === name && d.value.length === len &&
        !hasOwn(d.value, "prototype") && !hasOwn(d.value, "arguments") && !hasOwn(d.value, "caller");
    });
    return checked > 0 && ok;
  }, true);

  // call/new TypeError traps: platform objects reject wrong invocations in ways
  // JS monkey-patch almost never reproduces — patch written as plain function
  // is constructable, never brand-checks its receiver. Each trap asserts ONLY
  // that TypeError is thrown; trap that can't run resolves to pass.
  const nativeCallNewOK = () => safe(() => {
    const traps = [
      // WebIDL operation is not constructor: `new query()` must throw.
      () => typeof navigator === "undefined" || !navigator.permissions ||
        threwTypeError(() => new (navigator.permissions.query)()),
      // Platform class constructor called WITHOUT new must throw ("Illegal
      // constructor"); JS shim commonly forgets to enforce it.
      () => typeof HTMLElement !== "function" ||
        threwTypeError(() => HTMLElement()),
      // WebIDL method brand-checks its receiver: foreign `this` must throw
      // ("Illegal invocation"); plain-function patch never checks.
      () => typeof HTMLCanvasElement !== "function" ||
        threwTypeError(() => HTMLCanvasElement.prototype.toDataURL.call(document.createElement("div"))),
      () => typeof WebGLRenderingContext !== "function" ||
        threwTypeError(() => WebGLRenderingContext.prototype.getParameter.call(null, 0)),
    ];
    return traps.every((t) => safe(t, true)); // trap that can't run ⇒ pass, never flag
  }, true);

  // Function.prototype.toString Proxy detection — puppeteer-extra-stealth
  // hallmark. TRUE = BAD (inverted polarity vs other probes). Two independent
  // tells, each firing only on confident contradiction:
  //
  // Tell A — shape differential vs control native. Pristine toString is
  //   native non-constructor method (no own 'prototype', `new` throws TypeError)
  //   — same for Function.prototype.call. Proxy forwards these traits from its
  //   target → stealth build whose target is ORDINARY function makes toString
  //   disagree w/ control. Only DISAGREEMENT fires: engine quirk would hit both
  //   alike → reads as "can't tell".
  //
  // Tell B — error-stack trap frames (CreepJS queryLies-style). Calling proxied
  //   function routes through attacker's JS trap → when native under it throws
  //   (guaranteed here by illegal `this`), trap's own frame lands in err.stack.
  //   Pristine engine throws straight at our call site — `.call` invocation
  //   never produces extra trap frame. Message text never asserted; unreadable
  //   or empty stack is "can't tell" ⇒ false.
  //
  //   2026-07-19 audit note: original regex (`at\s+\S*apply\b|\bapply@`)
  //   assumed V8 names Proxy trap's frame as plain "at Object.apply" /
  //   "at Function.apply" — true on older V8 puppeteer-extra-stealth's own
  //   anchor-stripping (`stripProxyFromErrors` in its `_utils/index.js`) was
  //   written against. Current V8 (Chrome 150) instead renders it as ALIAS
  //   frame, e.g. "at newHandler.<computed> [as apply]" — old regex never
  //   matched → tell silently never fired (confirmed evaded in multi-framework
  //   matrix run). Alias format also means stealth's OWN anchor search (looks
  //   for literal "Object.newHandler.<computed> [as " prefix) misses too, on
  //   this V8, on very first illegal call — no double-nesting needed, its
  //   stripping is just no-op here. Verified via
  //   `automation-harness/frameworks/puppeteer-extra-stealth`: unmodified
  //   stealth 2.11.2 leaks raw "[as apply]" frame on single throw; Playwright's
  //   un-stealthed headless Chromium + genuine unpatched Chromium (Electron)
  //   both throw clean, alias-free native stack for exact same call → broadened
  //   pattern doesn't pick up ordinary automation or ordinary browsers — only
  //   actual Proxy trap in the way.
  const TRAP_ALIAS_RE =
    /\[as (?:apply|construct|get|set|has|deleteProperty|defineProperty|getOwnPropertyDescriptor|ownKeys|getPrototypeOf|setPrototypeOf|isExtensible|preventExtensions)\]/;
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
    return /at\s+\S*apply\b|\bapply@/.test(frames) || TRAP_ALIAS_RE.test(frames);
  }, false); // any failure ⇒ false: never flag on doubt

  // ── v3 probes (G09/G10/G17/G22/G23) ─────────────────────────────────────────
  // Same conventions as G04 probes: OK bools fail to pass (false only on
  // confirmed anomaly), TRUE=BAD values default false on any probe failure,
  // strings/lists come out empty when probe can't run — Go treats empty as
  // "not supplied", never evidence.

  // navProtoDescriptorsOK (G17): per WebIDL, webdriver / plugins / languages are
  // accessor (getter-only) properties — enumerable, configurable, living on
  // Navigator.prototype, never own data properties on navigator instance —
  // getters are native. Spoof installed via defineProperty/assignment breaks
  // at least one of those. Only confident anomalies count: absent or
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

  // chromeRuntimeOK (G22): genuine window.chrome carries chrome.runtime whose
  // sendMessage/connect are native NON-CONSTRUCTOR methods — no own 'prototype',
  // `new fn()` throws TypeError. Stealth-bolted fake (plain or bound function)
  // carries prototype or constructs silently; exotic throw isn't TypeError
  // (CreepJS hasBadChromeRuntime). Fail-to-pass: absent chrome/runtime is no
  // confident contradiction — absence is no_chrome_object's territory.
  //
  // 2026-07-19 audit note: tried tightening to flag window.chrome existing
  // WITHOUT runtime at all (puppeteer-extra-plugin-stealth 2.11.2's chrome
  // evasion has exactly this shape — adds app/csi, omits runtime — evaded this
  // rule as originally written). Reverted after verification: official "Chrome
  // for Testing" binary itself lacks chrome.runtime entirely — headless AND
  // headful, even w/ --enable-automation stripped and navigator.webdriver
  // patched away. Means absence is property of this Chrome *distribution*, not
  // proof of automation or stealth, and no genuine consumer-Chrome sample in
  // this audit's environment to confirm it behaves differently. Shipping
  // tightened version risked scoring real human visitors on that build as
  // tampered — not worth it w/o verifying against actual consumer Chrome first.
  // See tools/botcheck/docs/testing/findings/2026-07-19-multi-framework-matrix-results.md for full note; left as open item.
  const chromeRuntimeOK = () => safe(() => {
    if (!("chrome" in window)) return true;
    const c = window.chrome;
    if (!c || typeof c !== "object" || !("runtime" in c)) return true;
    const rt = c.runtime;
    if (!rt || typeof rt !== "object") return true;
    for (const name of ["sendMessage", "connect"]) {
      const fn = rt[name];
      if (typeof fn !== "function") continue; // no confident contradiction
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

  // chromeLateInjection (G22): genuine Chrome creates window.chrome during page
  // setup → sits early among window keys; stealth patch bolting on fake chrome
  // object appends it late (CreepJS hasHighChromeIndex — 'chrome' in last ~50 of
  // both enumerable keys and own property names). TRUE = BAD.
  const chromeLateInjection = () => safe(() => {
    if (!("chrome" in window)) return false;
    return Object.keys(window).slice(-50).includes("chrome") &&
      Object.getOwnPropertyNames(window).slice(-50).includes("chrome");
  }, false);

  // jsEngine (G23): JS engine from Error-stack format — V8 (Chrome/Edge/Opera)
  // frames look like "    at fn (url:line:col)"; SpiderMonkey (Firefox) stacks
  // use "fn@url:line:col" AND Error carries proprietary fileName/lineNumber
  // properties; JavaScriptCore (Safari + every iOS browser) also uses
  // "fn@url:line:col" but no fileName/lineNumber. "" ⇒ couldn't tell
  // (blocked/empty stack), Go treats as no signal.
  const jsEngine = () => safe(() => {
    const e = new Error();
    const stack = String((e && e.stack) || "");
    if (stack.includes(" at ")) return "v8";
    if (typeof e.fileName === "string" && typeof e.lineNumber === "number") return "spidermonkey";
    if (stack.includes("@")) return "jsc";
    return "";
  }, "");

  // webrtcProbe (G09): open RTCPeerConnection against public STUN server, harvest
  // ICE candidate IPs for ~1.5s (same timeout shape as other async probes). mDNS
  // *.local obfuscation names skipped — carry no IP. Go compares only PUBLIC
  // candidates against connection's egress IP (VPN/proxy pierce), applies
  // private/link-local/address-family exclusions; every failure path here
  // resolves empty, never a signal.
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

  // imageProbe (G10): 1×1 data-URI GIF that MUST load in any real browser
  // (sannysoft "Broken Image Dimensions"). naturalWidth == 0 — or error event —
  // means images blocked/stripped, headless tell. TRUE = BAD; timeout or setup
  // error reads as "can't tell" ⇒ false.
  const imageProbe = () => new Promise((resolve) => {
    try {
      const img = new Image();
      const timer = setTimeout(() => resolve(false), 1500);
      img.onload = () => { clearTimeout(timer); resolve(img.naturalWidth === 0); };
      img.onerror = () => { clearTimeout(timer); resolve(true); };
      img.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
    } catch { resolve(false); }
  });

  // ── v4 probes (G15/G21): additive "env" section ───────────────────────
  // Same conventions as v3 probes, tightened: every value fails to ABSENT (key
  // simply never set) — unsupported API or failed query is "not supplied",
  // never zero that could read as evidence. Scored rules (matchmedia_missing,
  // netinfo_incoherent) v4-gated server-side; rest is entropy for raw dump,
  // deliberately never scored (user preferences and hardware capabilities are
  // not bot tells).

  // mediaProbe reads CSS media-query / display-capability surface (G15).
  // matchMedia itself is one capability flag: exists in every real browser →
  // Go's matchmedia_missing rule treats its absence on browser UA as
  // stripped-environment tell. Each query individually safe()d, set only when
  // resolved — browser w/o matchMedia at all yields just { matchMedia: false }.
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
    // color-gamut: report widest supported; srgb universal → fallback answer
    // whenever query API works at all.
    if (mq("(color-gamut: rec2020)") === true) out.gamut = "rec2020";
    else if (mq("(color-gamut: p3)") === true) out.gamut = "p3";
    else if (mq("(color-gamut: srgb)") !== null) out.gamut = "srgb";
    const dpr = safe(() => window.devicePixelRatio, 0);
    if (typeof dpr === "number" && isFinite(dpr) && dpr > 0) out.dpr = dpr;
    return out;
  };

  // connectionProbe samples navigator.connection (G21) — browser's own
  // network-quality estimate. API doesn't exist on most Firefox/Safari installs:
  // absence normal, resolves null, Go reads as "not supplied" (netinfo_incoherent
  // rule simply skips). Each field set only when it reports sensible value.
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

  // storageProbe reads storage quota estimate, rounded to whole MB (G21).
  // 0 = couldn't tell (API absent, estimate failed) — Go treats 0 as absent.
  // Quota feeds nothing but raw dump; deliberately no incognito heuristic
  // (that's G19, skipped in roadmap).
  const storageProbe = () => safe(
    () => navigator.storage?.estimate?.().then((e) => {
      const q = e && e.quota;
      return typeof q === "number" && isFinite(q) && q > 0 ? Math.round(q / 1048576) : 0;
    }, () => 0),
    Promise.resolve(0),
  );

  // permissionsProbe samples two Permissions API states (G21). Each name
  // individually fail-to-absent — older Safari rejects 'geolocation' — whole
  // sample null when API itself missing. Entropy only: states are user
  // choices, no rule ever scores them.
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

  // emeProbe asks whether ClearKey EME available (G21). true/false both
  // determined answers; null means probe couldn't run (no EME API, unexpected
  // error) — fail-to-absent, never evidence.
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

  // gpcProbe reads navigator.globalPrivacyControl (G21): boolean where browser
  // exposes it (Firefox), null elsewhere — absent, never false.
  const gpcProbe = () => safe(() => {
    const g = navigator.globalPrivacyControl;
    return typeof g === "boolean" ? g : null;
  }, null);

  // envSection assembles v4 env object from probes above. quota/perms/eme are
  // already-resolved async probe results from collect()'s one Promise.all →
  // adds no wall time to happy path.
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

  // webglGPU reads unmasked VENDOR and RENDERER from WEBGL_debug_renderer_info.
  // Go compares two against each other (vendor/renderer coherence, G07) and GPU
  // family against UA-claimed OS (G08). Any failure (no WebGL, extension
  // blocked) yields empty strings, Go treats as "not supplied", never a tell.
  const webglGPU = () => safe(() => {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    const ext = gl?.getExtension("WEBGL_debug_renderer_info");
    return {
      webglVendor: ext ? (gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || "") : "",
      webglRenderer: ext ? (gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "") : "",
    };
  }, { webglVendor: "", webglRenderer: "" });

  // canvasProbe draws same content twice: identical hashes ⇒ stable; blank
  // (all-transparent) result ⇒ blocked/headless. Randomised output (unequal
  // hashes) = noise-injecting anti-fingerprint tool.
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

  // detectFonts counts how many probe fonts render at different width than
  // generic baselines (classic measureText technique). -1 ⇒ couldn't measure.
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
    // First canvas text measurement after navigation can hit cold font cache,
    // return generic width for every probe — spurious "no fonts". Warm cache
    // w/ throwaway pass, then take real measurement.
    count();
    return count();
  }, -1);

  // iframeProxied — CreepJS hasIframeProxy. puppeteer-extra-stealth
  // iframe.contentWindow patch installs getter that THROWS when fresh srcdoc
  // frame's window read this early; genuine engine never throws here (Chrome
  // returns WindowProxy even detached, Firefox returns null). TRUE = BAD; any
  // setup failure reads as false (never flag on doubt).
  const iframeProxied = () => {
    try {
      const f = document.createElement("iframe");
      f.srcdoc = "botcheck";
      void f.contentWindow; // stealth getter throws here; real engine doesn't
      return false;
    } catch { return true; }
  };

  // iframeProbe re-reads navigator inside display:none iframe (second JS
  // context). Anti-detect tools commonly spoof only top frame's navigator →
  // any value iframe reports differently is consistency tell — including
  // navigator.webdriver, which stealth patches fix in top frame but forget in
  // fresh iframe realm (G11). Empty values mean read failed — never a signal.
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

  // workerProbe recomputes navigator values, runs CDP trap inside Web Worker
  // (third JS context) — top-frame-only spoof leaks here. Also tries
  // OffscreenCanvas WebGL unmasked-renderer read (CreepJS hasBadWebGL diff);
  // many browsers lack OffscreenCanvas WebGL, just yields "". Uses blob URL so
  // no separate file needed; resolves w/ fallback on timeout/error.
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

  // swProbe asks Service Worker at /botcheck-sw.js (served by app itself — blob:
  // URL can't be registered as SW) for its navigator values: fourth JS context to
  // cross-check. SW answers over MessageChannel port so we don't race global
  // message listener; unregistered afterward so nothing left behind on
  // visitor's browser. Every failure path resolves w/ empty values (no SW
  // support, slow first install, HTTPS-only restrictions) — never a signal.
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
    // fullVersionList is load-bearing G01 signal: UA-string spoof that edits
    // "Chrome/NNN" but leaves userAgentData intact disagrees w/ "Chromium"
    // brand entry Go compares against. platform is low-entropy (read directly);
    // fullVersionList is high-entropy, needs getHighEntropyValues — can REJECT
    // (e.g. NotAllowedError in sandbox), safe() only catches synchronous throws
    // → `.catch` stops rejection from aborting whole fingerprint.
    const hi = await safe(() => d?.getHighEntropyValues?.(["fullVersionList"])?.catch(() => null), null);
    return {
      platform: safe(() => d?.platform ?? "", ""),
      fullVersionList: hi?.fullVersionList ?? [],
    };
  };

  // engineFamily feature-detects real rendering engine, independent of
  // (spoofable) UA string: gecko (Firefox), webkit (Safari + all iOS browsers),
  // blink (Chrome/Edge/Opera/Chromium). Each probe reads capability unique to
  // one engine; Go compares result to engine UA claims. "" ⇒ couldn't tell.
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
        storageProbe(), permissionsProbe(), emeProbe()], // v4: parallel with the rest — no added wall time
    );
    return {
      // Payload version. Bump when new field is damning-when-false (missing key
      // binds false server-side): Go skips those rules on older payloads →
      // stale cached copy of this file never reads as tampered. v2 = G04
      // probes; v3 = G09–G14/G17/G22/G23 batch + Layer-1 backlog fields; v4 =
      // G15/G21 "env" section (media queries, connection, storage, EME, GPC).
      v: 4,
      webdriver: safe(() => navigator.webdriver === true, false),
      frameworkGlobals: frameworkGlobals(),
      cdpMainThread: cdpTrap(),
      cdpWorker: !!worker.cdp,
      nativeToStringOK: nativeToStringOK(),
      nativeDescriptorsOK: nativeDescriptorsOK(), // G04 deep probes — same fail-to-pass
      nativeCallNewOK: nativeCallNewOK(), // convention: false only on confirmed tamper
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
      // G03: same navigator values re-read in other JS contexts. Top-frame-only
      // spoof leaves these untouched → Go diffs each against main thread's
      // claim. Empty/0 ⇒ context didn't answer — never a signal.
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
      // v3 batch: G09–G14/G17/G22/G23 signals + Layer-1 backlog fields. OK
      // bools fail to pass (gated on v server-side); TRUE=BAD booleans and
      // value fields default safe on stale payload.
      iframeWebdriver: iframe.webdriver === true, // G11: webdriver re-read in iframe
      iframeProxied: iframe.proxied === true, // G11: iframe contentWindow Proxy (true = bad)
      swWebdriver: sw.webdriver === true, // G14: webdriver in Service Worker
      swCDP: !!sw.cdp, // G14: CDP Error.stack trap, in Service Worker
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
      // v4 batch (G15/G21): one additive env section — media-query/display
      // values, connection sample, storage quota, permissions, EME, GPC. Every
      // key inside fails to absent; scored rules are v4-gated, rest is entropy
      // for raw dump only.
      env: envSection(quotaMB, perms, eme),
    };
  };

  // ── G46: returning-visitor history (localStorage only, never uploaded) ────
  // After each completed run, append {ts, score, verdict} — read off swapped-in
  // verdict card's data attrs — to botcheck:history list (capped at 20 most
  // recent), re-render "your recent checks" card. Every step goes through
  // safe(): private mode can make any localStorage access throw, history is
  // best-effort — must never break result flow.
  const HISTORY_KEY = "botcheck:history";
  const HISTORY_MAX = 20;
  const VERDICT_CLASS = { human: "text-ok", suspicious: "text-warn", "good-bot": "text-brand" };

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

  // Auto-run once page warmed up. Probes touching font cache and media
  // pipeline can read "cold" at DOMContentLoaded — spurious "no fonts / no
  // codecs" — proxy extension slowing load makes that far more likely. Wait
  // for load event and document.fonts.ready so those reads are stable, w/
  // timeout fallback so stalled resource never leaves page on "analyzing".
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
