import test from "node:test";
import assert from "node:assert/strict";
import {
  parseProcStat, parseProcStatus, parsePS, cpuPercent,
  formatBytes, formatPercent, formatDuration,
  sortProcesses, filterProcesses, mergePlatforms, totals,
  groupByOwner, endTaskDecision, redactCommandLine, confirmationFor,
  pushRing, sparkPath, processKey,
} from "./lib.mjs";

test("parseProcStat reads a comm with spaces and parentheses", () => {
  const line = "8124 (node (vite) worker) S 1 8124 8124 0 -1 4194304 100 0 0 0 30 20 0 0 20 0 1 0 12345 1000000 250 18446744073709551615";
  const p = parseProcStat(line);
  assert.equal(p.pid, 8124);
  assert.equal(p.name, "node (vite) worker");
  assert.equal(p.state, "S");
  assert.equal(p.ppid, 1);
  assert.equal(p.cpuSeconds, (30 + 20) / 100);
  assert.equal(p.threads, 1);
  assert.equal(p.startKey, "12345");
  assert.equal(p.rssBytes, 250 * 4096);
});

test("parseProcStat refuses malformed input", () => {
  assert.equal(parseProcStat(""), null);
  assert.equal(parseProcStat("1 (x) S 1"), null);
});

test("parseProcStatus and parsePS", () => {
  const s = parseProcStatus("Name:\tnode\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t  1200 kB\n");
  assert.equal(s.name, "node");
  assert.equal(s.uid, 1000);
  assert.equal(s.rssBytes, 1200 * 1024);
  const ps = parsePS("  10     1 01:02:03  2048 /usr/bin/node\n  11     1 00:05  100 /bin/sh\n");
  assert.equal(ps.length, 2);
  assert.equal(ps[0].cpuSeconds, 3723);
  assert.equal(ps[0].rssBytes, 2048 * 1024);
  assert.equal(ps[0].name, "node");
  assert.equal(ps[1].cpuSeconds, 5);
});

test("cpuPercent is a share of the whole machine", () => {
  assert.equal(cpuPercent(null, 10, 2000, 8), null);
  assert.equal(cpuPercent(0, 1, 1000, 8), 12.5);
  assert.equal(cpuPercent(0, 8, 1000, 8), 100);
  assert.equal(cpuPercent(10, 5, 1000, 8), 0);
  assert.equal(cpuPercent(0, 1, 0, 8), null);
});

test("formatting says what it knows", () => {
  assert.equal(formatBytes(0), "—");
  assert.equal(formatBytes(1024), "1 KB");
  assert.equal(formatBytes(10 * 1024), "10 KB");
  assert.equal(formatBytes(11.2 * 1024 ** 3), "11 GB");
  assert.equal(formatPercent(null), "—");
  assert.equal(formatPercent(0.44), "0.4%");
  assert.equal(formatPercent(18.4), "18%");
  assert.equal(formatDuration(128), "2m 08s");
  assert.equal(formatDuration(3723), "1h 02m");
});

test("sort keeps unknown CPU after known values and is stable", () => {
  const list = [
    { pid: 2, name: "b", cpuPct: 5, memBytes: 10 },
    { pid: 1, name: "a", cpuPct: null, memBytes: 30 },
    { pid: 3, name: "c", cpuPct: 5, memBytes: 20 },
  ];
  assert.deepEqual(sortProcesses(list, "cpu").map((p) => p.pid), [2, 3, 1]);
  assert.deepEqual(sortProcesses(list, "mem").map((p) => p.pid), [1, 3, 2]);
  assert.deepEqual(sortProcesses(list, "cpu", "asc").map((p) => p.pid), [1, 2, 3]);
});

test("filter matches name, pid, owner and workspace", () => {
  const list = [
    { name: "node", pid: 10, owner: { agent: "Claude Code", workspace: "picode" } },
    { name: "vite", pid: 11, owner: { agent: "", workspace: "web" } },
  ];
  assert.equal(filterProcesses(list, "claude").length, 1);
  assert.equal(filterProcesses(list, "web")[0].name, "vite");
  assert.equal(filterProcesses(list, "10")[0].name, "node");
  assert.equal(filterProcesses(list, "").length, 2);
});

test("mergePlatforms keeps the two PID namespaces apart", () => {
  const merged = mergePlatforms(
    [{ pid: 8124, name: "node", startKey: "1", cpuPct: 5, memBytes: 100 }],
    [{ pid: 8124, name: "msedge.exe", startKey: "2", workingSet: 50, denied: false }],
  );
  assert.equal(merged.length, 2);
  assert.equal(new Set(merged.map((p) => p.key)).size, 2);
  assert.equal(merged[0].key, processKey("linux", 8124, "1"));
  assert.equal(merged[1].platform, "windows");
  assert.equal(merged[1].memBytes, 50);
  assert.equal(merged[1].sameUser, true);
});

test("totals and groupByOwner", () => {
  const list = [
    { pid: 1, name: "node", cpuPct: 10, memBytes: 100, platform: "linux" },
    { pid: 2, name: "claude", cpuPct: 5, memBytes: 50, platform: "linux" },
    { pid: 3, name: "msedge.exe", cpuPct: 2, memBytes: 200, platform: "windows" },
  ];
  const t = totals(list, 8, 1000);
  assert.equal(t.cpuPct, 17);
  assert.equal(t.memBytes, 350);
  assert.equal(t.count, 3);
  assert.equal(totals([{ cpuPct: null, memBytes: 1 }], 8, 1000).cpuPct, null);
  const groups = groupByOwner(list, { 1: { agent: "Claude Code", workspace: "picode", confidence: "exact" }, 2: { agent: "Claude Code", workspace: "picode", confidence: "exact" } });
  assert.equal(groups[0].name, "Claude Code");
  assert.equal(groups[0].count, 2);
  assert.equal(groups[0].cpuPct, 15);
  assert.equal(groups[0].top.pid, 1);
  assert.equal(groups.find((g) => g.name === "Other").count, 1);
});

test("endTaskDecision covers the table", () => {
  const proc = { name: "node", startKey: "9" };
  const own = { pid: 42, startKey: "9", platform: "linux", proc, selfPid: 7, sameUser: true };
  assert.equal(endTaskDecision(own).ok, true);
  assert.equal(endTaskDecision({ ...own, pid: 0 }).ok, false);
  assert.equal(endTaskDecision({ ...own, pid: 7 }).ok, false);
  assert.equal(endTaskDecision({ ...own, protectedPids: new Set([42]) }).ok, false);
  assert.equal(endTaskDecision({ ...own, proc: null }).ok, false);
  assert.equal(endTaskDecision({ ...own, startKey: "8" }).ok, false);
  assert.equal(endTaskDecision({ ...own, proc: { name: "systemd", startKey: "9" } }).ok, false);
  assert.equal(endTaskDecision({ ...own, denied: true }).ok, false);
  assert.equal(endTaskDecision({ ...own, sameUser: false }).ok, false);
  assert.equal(endTaskDecision({ pid: 42, startKey: "", platform: "windows", proc: { name: "notepad.exe", startKey: "" } }).ok, false);
});

test("redactCommandLine masks secrets and URLs", () => {
  assert.equal(redactCommandLine("claude --token=abc123 --model x"), "claude --token=*** --model x");
  assert.equal(redactCommandLine("curl -H 'Authorization: Bearer abcdefghijklmnop'"), "curl -H 'Authorization: Bearer ***'");
  assert.equal(redactCommandLine("node app.js API_KEY=supersecret"), "node app.js API_KEY=***");
  assert.equal(redactCommandLine("git clone https://user:pass@example.com/x"), "git clone https://***@example.com/x");
  assert.equal(redactCommandLine("openai sk-abcdefghijklmnop"), "openai sk-***");
  assert.equal(redactCommandLine("a".repeat(600)).length, 498);
});

test("confirmation is bounded and dangerous", () => {
  const c = confirmationFor({ name: "node", pid: 42, revision: "a".repeat(64) });
  assert.equal(c.danger, true);
  assert.equal(c.confirmLabel, "End task");
  assert.ok(c.title.length <= 200);
  assert.ok(c.message.length <= 2000);
});

test("history rings and sparklines ignore gaps", () => {
  let ring = [];
  for (const v of [1, 2, null, 4]) ring = pushRing(ring, v, 3);
  assert.deepEqual(ring, [2, null, 4]);
  assert.equal(sparkPath([null, null]), "");
  assert.match(sparkPath([1, 2, 3]), /^M0\.0 11\.7/);
});
