/**
 * The metrics registry.
 *
 * The output of this module is parsed by Prometheus, which is unforgiving:
 * malformed exposition doesn't degrade, it drops the whole scrape. So the tests
 * are mostly about the text format being exactly right.
 */
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { metrics } from "@argus/shared";

beforeEach(() => metrics.reset());

test("counters accumulate per label set", () => {
  metrics.inc("reqs", { route: "/a" });
  metrics.inc("reqs", { route: "/a" });
  metrics.inc("reqs", { route: "/b" }, 5);
  const out = metrics.render();
  assert.match(out, /reqs\{route="\/a"\} 2/);
  assert.match(out, /reqs\{route="\/b"\} 5/);
});

test("gauges replace rather than accumulate", () => {
  metrics.set("depth", 10, { group: "g" });
  metrics.set("depth", 3, { group: "g" });
  assert.match(metrics.render(), /depth\{group="g"\} 3/);
});

test("label order is stable regardless of insertion order", () => {
  // Two series that differ only in key order must be ONE series, or a counter
  // silently splits in two and every rate() over it is wrong.
  metrics.inc("x", { b: "2", a: "1" });
  metrics.inc("x", { a: "1", b: "2" });
  assert.match(metrics.render(), /x\{a="1",b="2"\} 2/);
});

test("histograms emit cumulative buckets, sum and count", () => {
  for (const v of [3, 30, 300]) metrics.observe("dur", v, { route: "/x" });
  const out = metrics.render();
  assert.match(out, /dur_bucket\{le="5",route="\/x"\} 1/);   // only the 3
  assert.match(out, /dur_bucket\{le="50",route="\/x"\} 2/);  // 3 and 30
  assert.match(out, /dur_bucket\{le="\+Inf",route="\/x"\} 3/);
  assert.match(out, /dur_sum\{route="\/x"\} 333/);
  assert.match(out, /dur_count\{route="\/x"\} 3/);
});

test("buckets really are cumulative, not exclusive", () => {
  // The classic mistake. A non-cumulative histogram makes every quantile wrong
  // in a way that still looks plausible on a dashboard.
  metrics.observe("d2", 1);
  const out = metrics.render();
  const le10 = /d2_bucket\{le="10"\} (\d+)/.exec(out)![1];
  const le100 = /d2_bucket\{le="100"\} (\d+)/.exec(out)![1];
  assert.ok(Number(le100) >= Number(le10));
});

test("HELP and TYPE lines are emitted for every series", () => {
  metrics.inc("c", {}, 1, "a counter");
  const out = metrics.render();
  assert.match(out, /# HELP c a counter/);
  assert.match(out, /# TYPE c counter/);
});

test("label values are escaped", () => {
  // An unescaped quote or newline in a label breaks the parse for the entire
  // scrape, not just that line.
  metrics.inc("e", { msg: 'a "quoted" \\ value\nnewline' });
  const out = metrics.render();
  assert.match(out, /msg="a \\"quoted\\" \\\\ value\\nnewline"/);
  assert.ok(!out.includes('msg="a "quoted"'), "raw quote leaked into output");
});

test("unlabelled series render without braces", () => {
  metrics.inc("plain");
  assert.match(metrics.render(), /^plain 1$/m);
});

test("output ends with a newline", () => {
  // Prometheus rejects a body whose final line is unterminated.
  metrics.inc("z");
  assert.ok(metrics.render().endsWith("\n"));
});
