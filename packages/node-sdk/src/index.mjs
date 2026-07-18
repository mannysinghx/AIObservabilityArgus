// ESM entry — re-exports the CommonJS implementation so both
//   import argus from '@argus/node'
//   import { init, middleware } from '@argus/node'
// work identically to require('@argus/node').
import api from "./index.js";

export default api;
export const init = api.init;
export const middleware = api.middleware;
export const retrieval = api.retrieval;
export const tool = api.tool;
export const generation = api.generation;
export const annotate = api.annotate;
export const trace = api.trace;
export const activeTrace = api.activeTrace;
export const flush = api.flush;
export const shutdown = api.shutdown;
export const version = api.version;
