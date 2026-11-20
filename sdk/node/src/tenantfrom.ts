import type { Schema } from "./schema.ts";

/**
 * Declarative tenant resolution for tables that have no tenant column of their own.
 * `Mensagem: { via: "conversaId", model: "Conversa" }` means: a Mensagem belongs to the tenant of its Conversa.
 */
export interface TenantFromRule {
  /** Foreign-key scalar on this model (e.g. `conversaId`). */
  via: string;
  /** Parent model (e.g. `Conversa`). The parent may itself be resolved through its own rule. */
  model: string;
  /** Tenant column on the parent (default: the global `tenantField`, `tenantId`). */
  field?: string;
  /** Relation field on this model that points to the parent (inferred when omitted); used for `where: { conversa: { is: { tenantId } } }`. */
  relation?: string;
}

export interface TenantDeriverOptions {
  tenantFrom?: Record<string, TenantFromRule>;
  /** Name of the tenant column used on tenant-owned models (default `tenantId`). */
  tenantField?: string;
  /**
   * Also derive the tenant of models that HAVE a tenant column from data / create / where (and, for `where: { id }` alone, by lookup).
   * Off by default: the ambient tenant is the authorisation context, and deriving it from the query itself would let a handler that
   * forgot `withTenant` read any tenant's rows instead of failing closed.
   */
  fromArgs?: boolean;
  /** The BASE (un-extended) client, used for the id -> tenant lookups. */
  client?: () => any;
  /** Max cached id -> tenant entries (default 10 000). A row never changes tenant, so entries do not expire. */
  cacheSize?: number;
}

const isObj = (v: unknown): v is Record<string, any> => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : isObj(v) && typeof v.equals === "string" && v.equals ? v.equals : undefined);
const lowerFirst = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);

/** One value shared by every element, else undefined. */
const shared = (vals: (string | undefined)[]): string | undefined => {
  if (vals.length === 0) return undefined;
  const f = vals[0];
  return f !== undefined && vals.every((v) => v === f) ? f : undefined;
};

/** Find `key` in args.data / create / where (top level and inside AND), also across createMany rows. */
function fieldFromArgs(args: any, key: string): string | undefined {
  if (!isObj(args)) return undefined;
  const pick = (src: unknown): string | undefined => {
    if (Array.isArray(src)) return shared(src.map((r) => (isObj(r) ? str(r[key]) : undefined)));
    if (!isObj(src)) return undefined;
    const direct = str(src[key]);
    if (direct) return direct;
    if (Array.isArray(src.AND)) for (const w of src.AND) if (isObj(w) && str(w[key])) return str(w[key]);
    if (isObj(src.AND) && str(src.AND[key])) return str(src.AND[key]);
    return undefined;
  };
  return pick(args.data) ?? pick(args.create) ?? pick(args.where);
}

export function createTenantDeriver(schema: Schema, o: TenantDeriverOptions) {
  const rules = o.tenantFrom ?? {};
  const tenantField = o.tenantField ?? "tenantId";
  const max = o.cacheSize ?? 10_000;
  const cache = new Map<string, string>();
  const remember = (k: string, v: string) => {
    if (cache.size >= max) cache.delete(cache.keys().next().value as string); // oldest first
    cache.set(k, v);
  };

  for (const [model, r] of Object.entries(rules)) {
    const m = schema.get(model);
    if (!m) throw new Error(`cryplus: tenantFrom.${model}: unknown model`);
    if (!m.fields.has(r.via)) throw new Error(`cryplus: tenantFrom.${model}: no field "${r.via}"`);
    if (!schema.has(r.model)) throw new Error(`cryplus: tenantFrom.${model}: unknown parent model ${r.model}`);
  }

  const relationOf = (model: string, rule: TenantFromRule): string | undefined =>
    rule.relation ?? [...schema.get(model)!.fields.values()].find((f) => f.relation === rule.model)?.name;

  /** Tenant owning row `id` of `model`, by lookup through the base client (cached). */
  async function tenantOfRow(model: string, id: string, depth = 0): Promise<string | undefined> {
    const key = model + "\0" + id;
    const hit = cache.get(key);
    if (hit) return hit;
    const client = o.client?.();
    const m = schema.get(model);
    if (!client || !m?.idField || depth > 5) return undefined;
    const delegate = client[lowerFirst(model)];
    if (!delegate) return undefined;
    const rule = rules[model];
    let t: string | undefined;
    if (m.fields.has(tenantField) && !rule) {
      const row = await delegate.findUnique({ where: { [m.idField]: id }, select: { [tenantField]: true } });
      t = str(row?.[tenantField]);
    } else if (rule) {
      const row = await delegate.findUnique({ where: { [m.idField]: id }, select: { [rule.via]: true } });
      const parent = str(row?.[rule.via]);
      if (parent) t = await tenantOfParent(rule, parent, depth + 1);
    }
    if (t) remember(key, t);
    return t;
  }

  async function tenantOfParent(rule: TenantFromRule, parentId: string, depth: number): Promise<string | undefined> {
    const parentModel = schema.get(rule.model)!;
    const col = rule.field ?? tenantField;
    if (rule.field || (parentModel.fields.has(tenantField) && !rules[rule.model])) {
      const key = rule.model + "\0" + col + "\0" + parentId;
      const hit = cache.get(key);
      if (hit) return hit;
      const client = o.client?.();
      const delegate = client?.[lowerFirst(rule.model)];
      if (!delegate || !parentModel.idField) return undefined;
      const row = await delegate.findUnique({ where: { [parentModel.idField]: parentId }, select: { [col]: true } });
      const t = str(row?.[col]);
      if (t) remember(key, t);
      return t;
    }
    return tenantOfRow(rule.model, parentId, depth);
  }

  /**
   * Work out the tenant for `forModel` from the operation's arguments, without ambient context.
   * Sources, in order: the tenant column in data/create/where, the foreign key to the parent (looked up and cached),
   * a relation filter such as `where: { conversa: { is: { tenantId } } }`, and finally `where: { id }` alone.
   */
  return async function derive(forModel: string, opModel: string, args: any, viaRule = false): Promise<string | undefined> {
    const m = schema.get(forModel);
    if (!m) return undefined;
    const rule = rules[forModel];

    if (forModel !== opModel) {
      // a nested write/include: a child declared through the operation's own model shares that model's tenant
      if (rule && rule.model === opModel) return derive(opModel, opModel, args, true);
      return undefined;
    }

    if (m.fields.has(tenantField) && !rule) {
      if (!o.fromArgs && !viaRule) return undefined; // a parent is read from the query only on behalf of a declared tenantFrom rule
      const direct = fieldFromArgs(args, tenantField);
      if (direct) return direct;
      const id = m.idField ? fieldFromArgs({ where: args?.where }, m.idField) : undefined;
      return id ? tenantOfRow(forModel, id) : undefined;
    }
    if (!rule) return undefined;

    const relation = relationOf(forModel, rule);
    const col = rule.field ?? tenantField;

    // 1. a relation filter that already carries the tenant
    const w = isObj(args?.where) ? args.where : undefined;
    if (relation && w && isObj(w[relation])) {
      const f = isObj(w[relation].is) ? w[relation].is : w[relation];
      const direct = str(f?.[col]);
      if (direct) return direct;
    }
    // 2. the foreign key in data / create / where, or a connect
    let parentId = fieldFromArgs(args, rule.via);
    if (!parentId && relation) {
      const d = args?.data ?? args?.create;
      const conn = (x: any) => (isObj(x) && isObj(x[relation]) && isObj(x[relation].connect) ? str(x[relation].connect[schema.get(rule.model)!.idField ?? "id"]) : undefined);
      parentId = Array.isArray(d) ? shared(d.map(conn)) : conn(d);
      if (!parentId && w && isObj(w[relation])) parentId = str((w[relation].is ?? w[relation])?.[schema.get(rule.model)!.idField ?? "id"]);
    }
    if (parentId) return tenantOfParent(rule, parentId, 1);
    // 3. only the row's own id is known
    const id = m.idField ? fieldFromArgs({ where: args?.where }, m.idField) : undefined;
    return id ? tenantOfRow(forModel, id) : undefined;
  };
}

export type TenantDeriver = ReturnType<typeof createTenantDeriver>;
