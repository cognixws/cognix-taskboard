import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const PORT = Number(process.env.QA_PORT || 19777);
const TOKENS = path.join(ROOT, "..", "picode", "internal", "server", "artifactjs", "tokens.css");

function fixture() {
  const names = ["node", "claude", "codex", "vite", "msedge.exe", "Explorer.exe", "dockerd", "python3", "tmux", "sshd", "postgres", "cargo", "rustc", "chrome", "slack", "Code.exe", "pwsh.exe", "bash", "sleep", "gopls"];
  const owners = [
    { agent: "Claude Code", workspace: "picode", confidence: "exact" },
    { agent: "Codex", workspace: "api", confidence: "exact" },
    { agent: "", workspace: "web", confidence: "likely" },
    null,
  ];
  const list = [];
  for (let i = 0; i < 64; i++) {
    const name = names[i % names.length];
    const win = i % 5 === 0 || name.includes(".exe");
    const pid = win ? 4000 + i : 7000 + i;
    const owner = win ? null : owners[i % owners.length];
    const cpu = i === 0 ? 18.4 : i === 1 ? 7.1 : i < 8 ? 4.8 - i * 0.4 : i < 20 ? 1.6 - i * 0.05 : 0.1;
    list.push({
      pid, ppid: 1, name: win ? name : name.toLowerCase(), threads: 4 + (i % 20),
      platform: win ? "windows" : "linux", key: (win ? "windows" : "linux") + ":" + pid + ":" + (1000 + i),
      startKey: String(1000 + i), cpuPct: i === 63 ? null : Math.max(0, Number(cpu.toFixed(1))),
      memBytes: (win ? 80 + i * 14 : 30 + i * 9) * 1024 * 1024,
      readBytes: 1024 * (i * 7), writeBytes: 1024 * (i * 3), diskBps: i * 1024,
      sameUser: !win || i % 17 !== 0, denied: win && i % 17 === 0,
      protected: win && i % 17 === 0, owner,
      spark: Array.from({ length: 20 }, (_, k) => Math.max(0, cpu * (0.7 + 0.3 * Math.sin((k + i) / 3)))),
    });
  }
  const groups = [
    { key: "Claude Code", name: "Claude Code", agent: "Claude Code", workspace: "picode", confidence: "exact", count: 12, cpuPct: 21.4, memBytes: 2.1 * 1024 ** 3, top: { pid: 7000, name: "node", cpuPct: 18.4, memBytes: 1.9 * 1024 ** 3 } },
    { key: "Codex", name: "Codex", agent: "Codex", workspace: "api", confidence: "exact", count: 6, cpuPct: 8.2, memBytes: 780 * 1024 ** 2, top: { pid: 7001, name: "codex", cpuPct: 7.1, memBytes: 640 * 1024 ** 2 } },
    { key: "web", name: "web", agent: "", workspace: "web", confidence: "likely", count: 9, cpuPct: 4.1, memBytes: 1.4 * 1024 ** 3, top: { pid: 7003, name: "vite", cpuPct: 3.2, memBytes: 210 * 1024 ** 2 } },
    { key: "other", name: "Other", agent: "", workspace: "", confidence: "unknown", count: 37, cpuPct: 6.9, memBytes: 8.9 * 1024 ** 3, top: { pid: 4000, name: "msedge.exe", cpuPct: 4.8, memBytes: 820 * 1024 ** 2 } },
  ];
  const wave = (n, base, amp) => Array.from({ length: n }, (_, i) => Number((base + Math.sin(i / 6) * amp + Math.sin(i / 2.3) * amp * 0.25).toFixed(1)));
  return {
    at: new Date().toISOString(), sampledAt: Date.now(), intervalMs: 2000, paused: false,
    platform: "linux", version: "0.1.0",
    host: { name: "desktop", cpus: 24, memTotal: 31.8 * 1024 ** 3, memAvailable: 20.6 * 1024 ** 3, memUsed: 11.2 * 1024 ** 3, source: "windows" },
    windows: { applicable: true, available: true, reason: "" },
    totals: { cpuPct: 38.4, memBytes: 13.2 * 1024 ** 3, processMem: 13.2 * 1024 ** 3, memTotal: 31.8 * 1024 ** 3, count: 412, cpus: 24, cpuKnown: 63 },
    processes: list, agents: groups,
    history: { cpu: wave(70, 34, 14).map((v) => Math.max(0, Math.min(100, v))), mem: wave(70, 11.2 * 1024 ** 3, 0.9 * 1024 ** 3), spanMs: 140000 },
    settings: { update_ms: 2000, show_windows: true, alerts: false },
    protectedPids: [1, 4242],
  };
}

const page = fs.readFileSync(path.join(ROOT, "ui", "processes.html"), "utf8");
const fake = `
<script>
(function () {
  var q = new URLSearchParams(location.search);
  document.documentElement.dataset.theme = q.get("theme") === "light" ? "light" : "dark";
  if (q.get("select")) setTimeout(function () { var r = document.querySelector("[data-key]"); if (r) r.click(); }, 700);
  if (q.get("cmd")) setTimeout(function () {
    var r = document.querySelector('[data-key^="linux:"]'); if (r) r.click();
    setTimeout(function () { var b = document.querySelector('[data-act="cmd"]'); if (b) b.click(); }, 500);
  }, 700);
})();
window.picode = {
  use: function (name) {
    if (name === "process") return Promise.resolve({
      request: function (p, o) {
        if (p === "/snapshot" || p === "/refresh") return Promise.resolve({ status: 200, body: JSON.stringify(window.__FIXTURE__) });
        if (p === "/operations") return Promise.resolve({ status: 201, body: JSON.stringify({ operation: { id: "op-qa", status: "prepared" }, confirmation: { revision: "a".repeat(64) } }) });
        if (p === "/process/") return Promise.resolve({ status: 200, body: JSON.stringify({ cmdline: "node /home/me/picode --token=***", masked: true }) });
        if (p.indexOf("/process/") === 0) return Promise.resolve({ status: 200, body: JSON.stringify({ cmdline: "node /home/me/picode --token=***", masked: true }) });
        return Promise.resolve({ status: 200, body: "{}" });
      }
    });
    if (name === "confirm") return Promise.resolve({ operation: function () { return Promise.resolve({ confirmed: false }); } });
    if (name === "state") return Promise.resolve({
      get: function () {
        var q = new URLSearchParams(location.search);
        return Promise.resolve({ value: { lens: q.get("lens") || "processes", sort: q.get("sort") || "cpu", dir: q.get("dir") || "desc" } });
      },
      set: function () { return Promise.resolve({}); }
    });
    if (name === "links") return Promise.resolve({ open: function () {}, copy: function () {} });
    return Promise.resolve({});
  }
};
window.__FIXTURE__ = ${JSON.stringify(fixture())};
</script>
`;

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://127.0.0.1");
  if (u.pathname === "/__picode/tokens.css") {
    res.writeHead(200, { "Content-Type": "text/css; charset=utf-8" });
    return res.end(fs.readFileSync(TOKENS));
  }
  if (u.pathname === "/ui/processes.html" || u.pathname === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    return res.end(page.replace("</head>", fake + "</head>"));
  }
  res.writeHead(404).end("not found");
});

server.listen(PORT, "127.0.0.1", () => console.log("preview http://127.0.0.1:" + PORT + "/ui/processes.html"));
