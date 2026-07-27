"use strict";
// Replace a named export on a provider SDK's module object.
//
// Modern provider SDKs compile their entry point to getter-only exports
// (`openai@5+`, `@anthropic-ai/sdk@0.6x+`), so the obvious `mod.Name = Patched`
// throws "Cannot set property Name of ... which has only a getter" and the
// SDK-level patch silently never installs. Those getters are still
// `configurable`, so defineProperty succeeds exactly where assignment fails.
//
// Returns true only if the export actually holds `value` afterwards, so callers
// can log a real failure instead of assuming success.

function redefine(mod, name, value) {
  try {
    mod[name] = value;
    if (mod[name] === value) return true;
  } catch {
    // Getter-only export — fall through to defineProperty.
  }
  try {
    Object.defineProperty(mod, name, {
      value,
      configurable: true,
      enumerable: true,
      writable: true,
    });
    return mod[name] === value;
  } catch {
    return false;
  }
}

module.exports = { redefine };
