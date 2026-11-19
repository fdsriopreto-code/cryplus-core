export interface BreakerOptions {
  /** Consecutive unreachable failures before the circuit opens (default 5). */
  failureThreshold?: number;
  /** How long it stays open before one probe call is let through (default 10 000 ms). */
  resetMs?: number;
}

export type BreakerState = "closed" | "open" | "half-open";

/**
 * Stops hammering a key service that is down: after `failureThreshold` consecutive unreachable errors every call fails
 * immediately (`circuit_open`) for `resetMs`, then exactly one probe is allowed; success closes it, failure re-opens it.
 * Only "unreachable" counts. An answer, even an error answer such as 403, proves the service is alive.
 */
export class CircuitBreaker {
  state: BreakerState = "closed";
  private failures = 0;
  private openedAt = 0;
  private probing = false;
  private threshold: number;
  private resetMs: number;
  private onTransition?: (to: BreakerState) => void;

  constructor(o: BreakerOptions = {}, onTransition?: (to: BreakerState) => void) {
    this.threshold = o.failureThreshold ?? 5;
    this.resetMs = o.resetMs ?? 10_000;
    this.onTransition = onTransition;
  }

  private set(to: BreakerState) {
    if (this.state !== to) {
      this.state = to;
      this.onTransition?.(to);
    }
  }

  allow(now = Date.now()): boolean {
    if (this.state === "closed") return true;
    if (this.state === "open") {
      if (now - this.openedAt < this.resetMs) return false;
      this.set("half-open");
      this.probing = true;
      return true;
    }
    if (this.probing) return false; // half-open: one probe at a time
    this.probing = true;
    return true;
  }

  success() {
    this.failures = 0;
    this.probing = false;
    this.set("closed");
  }

  failure(now = Date.now()) {
    this.probing = false;
    if (this.state === "half-open" || ++this.failures >= this.threshold) {
      this.openedAt = now;
      this.set("open");
    }
  }
}
