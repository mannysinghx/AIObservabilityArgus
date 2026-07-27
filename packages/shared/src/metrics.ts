/**
 * Prometheus metrics.
 *
 * Argus had none. `/health` returned "ok" or "degraded" and that was the whole
 * of its self-knowledge: no queue depth, no consumer lag, no throughput, no
 * error rate. That is an awkward gap in an observability product, and a
 * practical one — you cannot operate what you cannot see, and the failure this
 * platform is most likely to have is the quiet kind (a stalled consumer, a
 * detection service that stopped answering) where every process is still up and
 * data simply stops arriving.
 *
 * Deliberately a tiny in-process registry rather than prom-client: counters,
 * gauges and a fixed-bucket histogram are all that's needed, and a dependency
 * that pulls in a cluster-aware aggregator to serve four numbers isn't worth
 * the supply chain.
 */

type Labels = Record<string, string>;

interface Series {
  name: string;
  help: string;
  type: "counter" | "gauge" | "histogram";
  values: Map<string, { labels: Labels; value: number }>;
  /** Histograms only: cumulative bucket counts and running sum, per label set. */
  buckets?: Map<string, { labels: Labels; counts: number[]; sum: number; count: number }>;
}

/** Latency buckets in milliseconds. Chosen around what we actually care about:
 *  sub-100ms is healthy, past 5s something is wrong. */
const BUCKETS_MS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

const registry = new Map<string, Series>();

function keyOf(labels: Labels): string {
  const keys = Object.keys(labels).sort();
  return keys.map((k) => `${k}=${labels[k]}`).join(",");
}

function series(name: string, type: Series["type"], help: string): Series {
  let s = registry.get(name);
  if (!s) {
    s = { name, help, type, values: new Map() };
    if (type === "histogram") s.buckets = new Map();
    registry.set(name, s);
  }
  return s;
}

export const metrics = {
  /** Add to a counter (monotonic). */
  inc(name: string, labels: Labels = {}, by = 1, help = ""): void {
    const s = series(name, "counter", help || name);
    const k = keyOf(labels);
    const cur = s.values.get(k);
    if (cur) cur.value += by;
    else s.values.set(k, { labels, value: by });
  },

  /** Set a gauge (can go up or down). */
  set(name: string, value: number, labels: Labels = {}, help = ""): void {
    const s = series(name, "gauge", help || name);
    s.values.set(keyOf(labels), { labels, value });
  },

  /** Record an observation into a latency histogram. */
  observe(name: string, valueMs: number, labels: Labels = {}, help = ""): void {
    const s = series(name, "histogram", help || name);
    const k = keyOf(labels);
    let b = s.buckets!.get(k);
    if (!b) {
      b = { labels, counts: new Array(BUCKETS_MS.length).fill(0), sum: 0, count: 0 };
      s.buckets!.set(k, b);
    }
    b.sum += valueMs;
    b.count += 1;
    for (let i = 0; i < BUCKETS_MS.length; i++) {
      if (valueMs <= BUCKETS_MS[i]) b.counts[i] += 1;
    }
  },

  /** Render the registry in Prometheus text exposition format. */
  render(): string {
    const out: string[] = [];
    for (const s of registry.values()) {
      out.push(`# HELP ${s.name} ${s.help}`);
      out.push(`# TYPE ${s.name} ${s.type}`);
      if (s.type === "histogram") {
        for (const b of s.buckets!.values()) {
          const base = fmtLabels(b.labels);
          for (let i = 0; i < BUCKETS_MS.length; i++) {
            out.push(`${s.name}_bucket${fmtLabels({ ...b.labels, le: String(BUCKETS_MS[i]) })} ${b.counts[i]}`);
          }
          out.push(`${s.name}_bucket${fmtLabels({ ...b.labels, le: "+Inf" })} ${b.count}`);
          out.push(`${s.name}_sum${base} ${b.sum}`);
          out.push(`${s.name}_count${base} ${b.count}`);
        }
      } else {
        for (const v of s.values.values()) {
          out.push(`${s.name}${fmtLabels(v.labels)} ${v.value}`);
        }
      }
    }
    return out.join("\n") + "\n";
  },

  /** Test helper — drop everything. */
  reset(): void {
    registry.clear();
  },
};

function fmtLabels(labels: Labels): string {
  const keys = Object.keys(labels).sort();
  if (!keys.length) return "";
  // Escape per the exposition format: backslash, quote, newline.
  const parts = keys.map(
    (k) => `${k}="${String(labels[k]).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`,
  );
  return `{${parts.join(",")}}`;
}
