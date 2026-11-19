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
