import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PORT = 19000 + Math.floor(Math.random() * 500);
const SECRET = "test-" + Math.random().toString(16).slice(2);
const BASE = "http://127.0.0.1:" + PORT;
let child;
let data;
let extension;

function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function call(p, { method = "GET", body, secret = true } = {}) {
  const res = await fetch(BASE + p, {
    method,
    headers: {
      ...(secret ? { "X-PiCode-Proxy-Secret": SECRET } : {}),
      ...(body != null ? { "Content-Type": "application/json" } : {}),
    },
    body: body == null ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

before(async () => {
  data = fs.mkdtempSync(path.join(os.tmpdir(), "taskboard-test-"));
  extension = spawn(process.execPath, [path.join(HERE, "process.mjs")], {
    cwd: HERE,
    env: {
      ...process.env,
      PICODE_EXT_PORT: String(PORT),
      PICODE_EXT_PROXY_SECRET: SECRET,
      PICODE_EXT_DIR: HERE,
      PICODE_EXT_DATA: data,
      PICODE_URL: "",
      PICODE_EXT_TOKEN: "",
      TASKBOARD_TEST: "1",
      TASKBOARD_NOWIN: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  extension.stdout.on("data", (d) => { output += d; });
  extension.stderr.on("data", (d) => { output += d; });
  for (let i = 0; i < 60; i++) {
    if (output.includes("listening")) return;
    await wait(100);
  }
  throw new Error("the process did not start: " + output);
});

after(async () => {
  if (child) { try { child.kill("SIGKILL"); } catch { /* gone */ } }
  if (extension) { extension.kill("SIGTERM"); await wait(200); try { extension.kill("SIGKILL"); } catch { /* gone */ } }
  if (data) { try { fs.rmSync(data, { recursive: true, force: true }); } catch { /* gone */ } }
});

test("the relay secret is required", async () => {
  const r = await call("/snapshot", { secret: false });
  assert.equal(r.status, 403);
});

test("snapshot has real Linux processes and a machine total", async () => {
  const r = await call("/snapshot");
  assert.equal(r.status, 200);
  assert.ok(r.data.host.cpus >= 1);
  assert.ok(r.data.processes.length > 3, "expected processes");
  assert.ok(r.data.processes.some((p) => p.platform === "linux"));
  assert.ok(r.data.totals.count >= r.data.processes.length - 1);
  assert.equal(typeof r.data.host.memTotal, "number");
  assert.ok(Array.isArray(r.data.history.cpu));
});

test("end task refuses PID 1 and a stale start key", async () => {
  const snapshot = await call("/snapshot");
  const own = snapshot.data.processes.find((p) => p.pid === 1) || { pid: 1, startKey: "1" };
  const protectedOne = await call("/operations", { method: "POST", body: { action: "end", platform: "linux", pid: 1, startKey: own.startKey } });
  assert.equal(protectedOne.status, 409);
  const other = snapshot.data.processes.find((p) => p.pid !== 1 && p.platform === "linux");
  const stale = await call("/operations", { method: "POST", body: { action: "end", platform: "linux", pid: other.pid, startKey: "not-the-key" } });
  assert.equal(stale.status, 409);
});

test("end task needs the owner confirmation and then ends the process", async () => {
  child = spawn("bash", ["-c", "read -t 30 x", "--token=supersecret"]);
  await wait(250);
  const refreshed = await call("/refresh", { method: "POST" });
  assert.equal(refreshed.status, 200);
  const row = refreshed.data.processes.find((p) => p.pid === child.pid && p.platform === "linux");
  assert.ok(row, "the child should be in the snapshot");
  assert.equal(row.sameUser, true);

  const line = await call("/process/" + child.pid + "/cmdline");
  assert.equal(line.status, 200);
  assert.match(line.data.cmdline, /--token=\*\*\*/);

  const created = await call("/operations", { method: "POST", body: { action: "end", platform: "linux", pid: child.pid, startKey: row.startKey } });
  assert.equal(created.status, 201);
  assert.ok(created.data.confirmation.revision.match(/^[a-f0-9]{64}$/));
  assert.equal(created.data.confirmation.danger, true);
  assert.equal(created.data.confirmation.confirmLabel, "End task");
  const id = created.data.operation.id;

  const listed = await call("/operations/" + id);
  assert.equal(listed.status, 200);
  assert.equal(listed.data.confirmation.revision, created.data.confirmation.revision);

  const noHeader = await call("/__picode/confirm", { method: "POST", body: { operationId: id, revision: created.data.confirmation.revision } });
  assert.equal(noHeader.status, 403);

  const wrong = await fetch(BASE + "/__picode/confirm", {
    method: "POST",
    headers: { "X-PiCode-Proxy-Secret": SECRET, "X-PiCode-Owner-Confirmed": "0".repeat(64), "Content-Type": "application/json" },
    body: JSON.stringify({ operationId: id, revision: "0".repeat(64) }),
  });
  assert.equal(wrong.status, 403);

  const confirmed = await fetch(BASE + "/__picode/confirm", {
    method: "POST",
    headers: { "X-PiCode-Proxy-Secret": SECRET, "X-PiCode-Owner-Confirmed": created.data.confirmation.revision, "Content-Type": "application/json" },
    body: JSON.stringify({ operationId: id, revision: created.data.confirmation.revision }),
  });
  assert.equal(confirmed.status, 200);
  const answer = await confirmed.json();
  assert.equal(answer.operation.status, "done");
  await wait(300);
  assert.equal(alive(child.pid), false);
});
