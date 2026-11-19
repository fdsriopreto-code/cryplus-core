/** Where the SDK reports what it does. Implement it yourself, use `prometheusSink`, or just read `client.stats()`. */
export interface MetricsSink {
  inc(name: string, labels?: Record<string, string>, value?: number): void;
  observe(name: string, seconds: number, labels?: Record<string, string>): void;
}

/** Always-on in-process counters, readable through `client.stats()`. */
export class Stats implements MetricsSink {
  private c = new Map<string, number>();
  private sum = new Map<string, { n: number; total: number; max: number }>();
  private key(name: string, labels?: Record<string, string>) {
    if (!labels) return name;
    const l = Object.keys(labels).sort().map((k) => `${k}="${labels[k]}"`).join(",");
    return `${name}{${l}}`;
  }
  inc(name: string, labels?: Record<string, string>, value = 1) {
    const k = this.key(name, labels);
    this.c.set(k, (this.c.get(k) ?? 0) + value);
  }
  observe(name: string, seconds: number, labels?: Record<string, string>) {
    const k = this.key(name, labels);
    const s = this.sum.get(k) ?? { n: 0, total: 0, max: 0 };
    s.n++;
    s.total += seconds;
    s.max = Math.max(s.max, seconds);
    this.sum.set(k, s);
  }
  snapshot(): { counters: Record<string, number>; timings: Record<string, { count: number; avgMs: number; maxMs: number }> } {
    const timings: Record<string, { count: number; avgMs: number; maxMs: number }> = {};
    for (const [k, v] of this.sum) timings[k] = { count: v.n, avgMs: (v.total / v.n) * 1000, maxMs: v.max * 1000 };
    return { counters: Object.fromEntries(this.c), timings };
  }
  get(name: string, labels?: Record<string, string>): number {
    return this.c.get(this.key(name, labels)) ?? 0;
  }
}

/** Fan out to several sinks. */
export function combineSinks(...sinks: (MetricsSink | undefined)[]): MetricsSink {
  const live = sinks.filter((s): s is MetricsSink => !!s);
  return {
    inc: (n, l, v) => live.forEach((s) => s.inc(n, l, v)),
    observe: (n, x, l) => live.forEach((s) => s.observe(n, x, l)),
  };
}

/**
 * Metrics for `prom-client` without depending on it: pass the module you already use.
 *
 *   const prom = require("prom-client");
 *   const cryplus = new Cryplus({ metrics: prometheusSink(prom) });
 *
 * Exposed (prefix `cryplus_`): requests_total{op,mode,result}, request_seconds{op,mode}, errors_total{code},
 * key_cache_total{event=hit|miss|stale}, key_fetch_total{result}, breaker_transitions_total{to}, prisma_errors_total{code}.
 */
export function prometheusSink(prom: any, opts: { prefix?: string; registers?: any[] } = {}): MetricsSink {
  const prefix = opts.prefix ?? "cryplus_";
  const counters = new Map<string, any>();
  const histos = new Map<string, any>();
  const register = opts.registers ?? undefined;
  return {
    inc(name, labels = {}, value = 1) {
      const n = prefix + name;
      let c = counters.get(n);
      if (!c) {
        c = new prom.Counter({ name: n, help: `cryplus ${name}`, labelNames: Object.keys(labels), ...(register ? { registers: register } : {}) });
        counters.set(n, c);
      }
      c.inc(labels, value);
    },
    observe(name, seconds, labels = {}) {
      const n = prefix + name;
      let h = histos.get(n);
      if (!h) {
        h = new prom.Histogram({ name: n, help: `cryplus ${name}`, labelNames: Object.keys(labels), buckets: [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5], ...(register ? { registers: register } : {}) });
        histos.set(n, h);
      }
      h.observe(labels, seconds);
    },
  };
}
