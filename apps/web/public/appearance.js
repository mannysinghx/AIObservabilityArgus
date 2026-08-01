/**
 * Appearance preferences — applied before anything renders.
 *
 * This is a separate file loaded synchronously from <head>, deliberately, for
 * two reasons. It has to run before the first paint: a theme applied from app.js
 * (which loads at the end of <body>) would show a flash of the wrong colours on
 * every single page load, which looks broken and is worst for the people who
 * chose light mode because dark hurts to look at. And it cannot be an inline
 * <script>, because the CSP here is `script-src 'self'` with no unsafe-inline —
 * inlining it would mean maintaining a sha256 hash in the response headers to
 * match this content, and that coupling breaks silently the moment either side
 * is edited.
 *
 * Preferences live in localStorage. They are a device preference, not account
 * state: the same person may well want dark on a laptop at night and light on a
 * bright monitor, and syncing that to a server account would get it wrong on one
 * of them.
 */
(function () {
  "use strict";

  // key → the data-* attribute it sets on <html>. "system"/"" means "no
  // attribute", which is how the stylesheet expresses its default.
  var KEYS = {
    theme: "data-theme",
    accent: "data-accent",
    density: "data-density",
    radius: "data-radius",
    fontsize: "data-fontsize",
  };
  var STORE = "argus.appearance";

  function read() {
    try {
      return JSON.parse(localStorage.getItem(STORE) || "{}") || {};
    } catch (e) {
      // Corrupt or unavailable storage (private mode, quota, hand-edited value)
      // must not stop the dashboard rendering. Defaults are a fine outcome.
      return {};
    }
  }

  function apply(prefs) {
    var root = document.documentElement;
    for (var key in KEYS) {
      if (!Object.prototype.hasOwnProperty.call(KEYS, key)) continue;
      var val = prefs[key];
      if (!val || val === "system") root.removeAttribute(KEYS[key]);
      else root.setAttribute(KEYS[key], val);
    }
  }

  function save(key, val) {
    var prefs = read();
    prefs[key] = val;
    try {
      localStorage.setItem(STORE, JSON.stringify(prefs));
    } catch (e) {
      // Storage full or blocked — the change still applies for this session.
    }
    apply(prefs);
  }

  apply(read());

  // Exposed for app.js: the settings UI reads current values to light up the
  // right buttons, and writes through here so persistence and application stay
  // in one place.
  window.ArgusAppearance = { read: read, apply: apply, save: save, KEYS: KEYS };
})();
