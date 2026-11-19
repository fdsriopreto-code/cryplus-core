/**
 * Keep personal data and secrets out of Redis. BullMQ stores `job.data` in clear text; these helpers seal it before it
 * is enqueued and open it inside the worker, which also runs inside `withTenant` so the Prisma extension works there.
 *
 *   const queue  = encryptedQueue(new Queue("pdf-generation", { connection }), cryplus);
 *   await queue.add("render", { tenantId, orcamento });          // Redis now holds { __cryplus: 1, tenantId, sealed: "cp1..." }
 *   new Worker("pdf-generation", encryptedWorker(cryplus, async (job) => { ... job.data.orcamento ... }), { connection });
 *
 * What stays in clear in Redis: the job name, the queue name, job options (delay, attempts...), the TENANT ID (workers and
 * operators need it to route and to find a stuck job) and the envelope marker. Everything else in `data` is encrypted.
 * What these helpers do NOT cover: `job.returnvalue`, `failedReason`, stack traces and log lines (do not put secrets in them),
 * `job.updateData`, repeatable-job keys built from your data, and job ids you choose yourself.
 * Even better than sealing is not enqueueing the data at all: pass an id and let the worker read the row.
 */
import type { Context, CryplusApi } from "./client.ts";
import { currentTenant, withTenant } from "./tenant.ts";

export const SEALED_MARKER = "__cryplus";

export interface SealedJob {
  __cryplus: 1;
  tenantId: string;
  sealed: string;
}

export interface JobOptions {
  /** Where the tenant id lives in the job data (default "tenantId"). */
  tenantField?: string;
}

export const isSealedJob = (d: unknown): d is SealedJob =>
  !!d && typeof d === "object" && (d as any)[SEALED_MARKER] === 1 && typeof (d as any).sealed === "string" && typeof (d as any).tenantId === "string";

/** The encryption context of a job: bound to the queue and the job name, so a sealed payload cannot be replayed into another queue or job type. */
const ctxFor = (tenant: string, queue: string, name: string): Context => ({ tenant, collection: `queue:${queue}`, field: name });

function tenantOf(data: any, o: JobOptions): string {
  const t = (data && typeof data === "object" ? data[o.tenantField ?? "tenantId"] : undefined) ?? currentTenant();
  if (!t || typeof t !== "string") {
    throw new Error(`cryplus: no tenant for this job; put \`${o.tenantField ?? "tenantId"}\` in the job data or enqueue inside withTenant()`);
  }
  return t;
}

/** Encrypt job data for the given queue and job name. */
export async function sealJobData(cryplus: Pick<CryplusApi, "encrypt">, queue: string, name: string, data: unknown, o: JobOptions = {}): Promise<SealedJob> {
  const tenantId = tenantOf(data, o);
  const sealed = await cryplus.encrypt(ctxFor(tenantId, queue, name), JSON.stringify(data));
  return { __cryplus: 1, tenantId, sealed };
}

/** Decrypt sealed job data. Throws if it was sealed for another queue, job name or tenant. */
export async function openJobData<T = any>(cryplus: Pick<CryplusApi, "decrypt">, queue: string, name: string, data: SealedJob): Promise<T> {
  return JSON.parse(await cryplus.decrypt(ctxFor(data.tenantId, queue, name), data.sealed)) as T;
}

interface QueueLike {
  name: string;
  add(name: string, data: any, opts?: any): Promise<any>;
  addBulk?(jobs: { name: string; data: any; opts?: any }[]): Promise<any>;
}

/**
 * Wrap a BullMQ `Queue` so that `add` / `addBulk` seal `data` first. Everything else is passed through unchanged
 * (so it stays a drop-in replacement). Fails closed if no tenant can be determined.
 */
export function encryptedQueue<Q extends QueueLike>(queue: Q, cryplus: Pick<CryplusApi, "encrypt">, o: JobOptions = {}): Q {
  return new Proxy(queue, {
    get(target, prop, receiver) {
      if (prop === "add") {
        return async (name: string, data: any, opts?: any) => target.add(name, await sealJobData(cryplus, target.name, name, data, o), opts);
      }
      if (prop === "addBulk" && typeof target.addBulk === "function") {
        return async (jobs: { name: string; data: any; opts?: any }[]) =>
          target.addBulk!(await Promise.all(jobs.map(async (j) => ({ ...j, data: await sealJobData(cryplus, target.name, j.name, j.data, o) }))));
      }
      const v = Reflect.get(target, prop, receiver);
      return typeof v === "function" ? v.bind(target) : v;
    },
  }) as Q;
}

interface JobLike {
  name: string;
  queueName?: string;
  data: any;
}

export interface WorkerWrapOptions extends JobOptions {
  /** Process jobs that were enqueued before sealing was rolled out (default true). Set false once the queue has drained. */
  allowPlain?: boolean;
  /** The queue name, when the job object does not carry `queueName`. */
  queue?: string;
}

/**
 * Wrap a BullMQ processor: opens sealed `job.data` (in place, in memory only) and runs the processor inside
 * `withTenant(job tenant)`, so Prisma queries made by the processor use the right tenant without any extra code.
 * A sealed payload that does not open (wrong queue/job/tenant, tampering) fails the job; it is never processed.
 */
export function encryptedWorker<J extends JobLike, R>(
  cryplus: Pick<CryplusApi, "decrypt">,
  processor: (job: J, token?: string) => Promise<R> | R,
  o: WorkerWrapOptions = {},
): (job: J, token?: string) => Promise<R> {
  return async (job: J, token?: string) => {
    const queue = job.queueName ?? o.queue;
    if (isSealedJob(job.data)) {
      if (!queue) throw new Error("cryplus: cannot determine the queue name of this job (pass { queue } to encryptedWorker)");
      const tenantId = job.data.tenantId;
      job.data = await openJobData(cryplus, queue, job.name, job.data);
      return withTenant(tenantId, () => processor(job, token));
    }
    if (o.allowPlain === false) throw new Error("cryplus: refusing to process a job whose data is not sealed");
    const t = job.data && typeof job.data === "object" ? job.data[o.tenantField ?? "tenantId"] : undefined;
    return typeof t === "string" && t ? withTenant(t, () => processor(job, token)) : Promise.resolve(processor(job, token));
  };
}
