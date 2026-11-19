#!/usr/bin/env node
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { checkSchema } from "./schema.ts";
import { scanPaths } from "./scan.ts";

const HELP = `cryplus-scan: find raw SQL that touches @encrypted columns

Usage: cryplus-scan --schema prisma/schema.prisma --src src [--src lib ...] [options]

Options:
  --schema FILE        schema.prisma (required)
  --src DIR            directory (or file) to scan; repeatable (required)
  --ignore NAME        directory name to skip; repeatable (default: node_modules .git dist build generated coverage)
  --allow-dynamic      do not fail on SQL that cannot be analyzed (they are still listed)
  --format text|json   output format (default text)

Exit status: 0 clean, 1 findings (or unanalyzable SQL unless --allow-dynamic), 2 usage or schema error.
Silence a reviewed call with  // cryplus-ignore-next-line: <reason>  on the line before it.
`;

function main(argv: string[]): number {
  const src: string[] = [];
  const ignore: string[] = [];
  let schemaPath = "";
  let allowDynamic = false;
  let format = "text";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--schema") schemaPath = argv[++i] ?? "";
    else if (a === "--src") src.push(argv[++i] ?? "");
    else if (a === "--ignore") ignore.push(argv[++i] ?? "");
    else if (a === "--allow-dynamic") allowDynamic = true;
    else if (a === "--format") format = argv[++i] ?? "";
    else if (a === "-h" || a === "--help") {
      process.stdout.write(HELP);
      return 0;
    } else {
      process.stderr.write(`unknown argument ${a}\n${HELP}`);
      return 2;
    }
  }
  if (!schemaPath || src.length === 0 || !["text", "json"].includes(format)) {
    process.stderr.write(HELP);
    return 2;
  }
  const { schema, problems } = checkSchema(readFileSync(schemaPath, "utf8"));
  if (problems.length) {
    for (const p of problems) process.stderr.write(`schema: ${p.model}.${p.field}: ${p.message}${p.fix ? `\n    run first: ${p.fix}` : ""}\n`);
    return 2;
  }
  const { findings, files } = scanPaths(schema, src, ignore.length ? ignore : undefined);
  const errors = findings.filter((f) => f.severity === "error");
  const dynamic = findings.filter((f) => f.severity === "dynamic");
  if (format === "json") {
    process.stdout.write(JSON.stringify({ files, findings }, null, 2) + "\n");
  } else {
    for (const f of findings) {
      process.stdout.write(`${path.normalize(f.file)}:${f.line}:${f.column}  ${f.severity.padEnd(7)} ${f.call}  ${f.message}\n`);
    }
    process.stdout.write(`\ncryplus-scan: ${files} files, ${errors.length} error(s), ${dynamic.length} unanalyzable, ${findings.length - errors.length - dynamic.length} info\n`);
  }
  return errors.length > 0 || (dynamic.length > 0 && !allowDynamic) ? 1 : 0;
}

process.exit(main(process.argv.slice(2)));
