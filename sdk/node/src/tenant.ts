import { AsyncLocalStorage } from "node:async_hooks";

const als = new AsyncLocalStorage<string>();

/**
 * Run fn with an ambient tenant. Every encrypted Prisma operation inside it
 * (including awaited async work) uses this tenant's keys. Wrap each request
 * handler once, e.g. in middleware, after authenticating the user.
 *
 * Always returns a Promise. fn is awaited INSIDE the tenant scope on purpose:
 * Prisma queries are lazy and only run when awaited, so
 * `withTenant(id, () => prisma.user.findMany())` must trigger the query
 * before the scope ends.
 */
export function withTenant<T>(tenant: string, fn: () => T): Promise<Awaited<T>> {
  if (!tenant) throw new Error("cryplus: tenant must be a non-empty string");
  return als.run(tenant, async () => await fn()) as Promise<Awaited<T>>;
}

export function currentTenant(): string | undefined {
  return als.getStore();
}

/** Like withTenant but synchronous: runs fn with the ambient tenant and returns its result untouched (for middleware). */
export function runWithTenant<T>(tenant: string, fn: () => T): T {
  if (!tenant) throw new Error("cryplus: tenant must be a non-empty string");
  return als.run(tenant, fn);
}

/**
 * Express/Connect middleware that sets the ambient tenant for the rest of the request, including everything the handlers
 * `await` afterwards. `getTenant` may be async and may return undefined (login, webhooks, health): then no tenant is set
 * and the request continues. Put it AFTER authentication, once.
 *
 *   app.use(authenticate);
 *   app.use(cryplusTenantMiddleware((req) => req.user?.tenantId));
 */
export function cryplusTenantMiddleware<Req = any, Res = any>(
  getTenant: (req: Req) => string | undefined | null | Promise<string | undefined | null>,
): (req: Req, res: Res, next: (err?: unknown) => void) => void {
  return (req, _res, next) => {
    let t: ReturnType<typeof getTenant>;
    try {
      t = getTenant(req);
    } catch (e) {
      return next(e);
    }
    const go = (id: string | undefined | null) => (id ? runWithTenant(id, () => next()) : next());
    if (t && typeof (t as Promise<unknown>).then === "function") (t as Promise<string | undefined | null>).then(go, next);
    else go(t as string | undefined | null);
  };
}
