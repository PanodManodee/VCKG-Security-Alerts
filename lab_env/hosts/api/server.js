// REST API for the lab. All data is fake.
// /users and /orders are read from PostgreSQL on every request (lab/asset_edges.csv: API -> PostgreSQL),
// so the API really depends on the database: when PostgreSQL is down they return 503. The connection
// comes from the standard libpq environment (PGHOST, PGUSER, PGPASSWORD, PGDATABASE) and uses psql,
// which keeps the image free of npm dependencies.
// Every request is written to /var/log/api/access.log in Apache combined format, which the Wazuh
// agent reads with its web access-log rules.
const fs = require("fs");
const http = require("http");
const { execFile } = require("child_process");

function query(sql, columns) {
  return new Promise((resolve, reject) => {
    execFile("psql", ["-X", "-tA", "-F", "\t", "-c", sql], { timeout: 4000 }, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout.trim().split("\n").filter(Boolean).map((line) => {
        const cells = line.split("\t");
        return Object.fromEntries(columns.map((c, i) => [c, cells[i]]));
      }));
    });
  });
}

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

const routes = {
  "/": async () => ({ service: "acme-api", node: process.version }),
  "/health": async () => ({ status: "ok" }),           // the API process itself, no database
  "/users": () => query("select id, name, email from customers order by id", ["id", "name", "email"]),
  "/orders": () => query("select id, customer_id, sku, qty from orders order by id", ["id", "customer_id", "sku", "qty"]),
};

http
  .createServer(async (req, res) => {
    const route = routes[req.url.split("?")[0]];
    let status = 200, body;
    if (!route) {
      status = 404; body = { error: "not found" };
    } else {
      try {
        body = await route();
      } catch (err) {
        status = 503; body = { error: "database unavailable" };
      }
    }
    const payload = JSON.stringify(body);
    res.writeHead(status, { "Content-Type": "application/json", "X-Powered-By": `Node.js ${process.version}` });
    res.end(payload);
    logRequest(req, status, Buffer.byteLength(payload));
  })
  .listen(3000, "0.0.0.0", () => console.log(`acme-api listening on :3000 (${process.version})`));
