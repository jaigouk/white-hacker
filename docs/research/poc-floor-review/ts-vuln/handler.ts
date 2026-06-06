import { exec } from "child_process";
import express from "express";

const app = express();

// VULN (planted): OS command injection — user `name` is interpolated into a
// shell command string passed to exec(). Category: injection. OWASP A03:2025.
app.get("/greet", (req, res) => {
  const name = String(req.query.name);
  exec(`echo Hello ${name}`, (_e, stdout) => res.send(stdout));
});

export default app;
