// Dummy REST API for the lab (no dependencies). All data is fake.
// Every request is written to /var/log/api/access.log in Apache combined format, which the Wazuh
// agent reads with its web access-log rules.
const fs = require("fs");
const http = require("http");

fs.mkdirSync("/var/log/api", { recursive: true });
const accessLog = fs.createWriteStream("/var/log/api/access.log", { flags: "a" });
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (n) => String(n).padStart(2, "0");
function clfDate(d) {
  return `${pad(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}
function logRequest(req, status, bytes) {
  const ip = (req.socket.remoteAddress || "-").replace(/^::ffff:/, "");
  const ua = req.headers["user-agent"] || "-";
  const ref = req.headers["referer"] || "-";
  accessLog.write(`${ip} - - [${clfDate(new Date())}] "${req.method} ${req.url} HTTP/${req.httpVersion}" ` +
    `${status} ${bytes} "${ref}" "${ua}"\n`);
}

const users = [
  { id: 1, name: "Alice Example", email: "alice@lab.local", role: "admin" },
  { id: 2, name: "Bob Example", email: "bob@lab.local", role: "staff" },
];
const orders = [
  { id: 1001, user_id: 2, sku: "A-100", qty: 3 },
  { id: 1002, user_id: 1, sku: "A-200", qty: 1 },
];

const routes = {
  "/": { service: "acme-api", node: process.version },
  "/health": { status: "ok" },
  "/users": users,
  "/orders": orders,
};

http
  .createServer((req, res) => {
    const body = routes[req.url.split("?")[0]];
    const status = body ? 200 : 404;
    const payload = JSON.stringify(body ?? { error: "not found" });
    res.writeHead(status, { "Content-Type": "application/json", "X-Powered-By": `Node.js ${process.version}` });
    res.end(payload);
    logRequest(req, status, Buffer.byteLength(payload));
  })
  .listen(3000, "0.0.0.0", () => console.log(`acme-api listening on :3000 (${process.version})`));
