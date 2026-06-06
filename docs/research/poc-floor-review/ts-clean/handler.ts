import { execFile } from "child_process";
import express from "express";

const app = express();

// SAFE look-alike: execFile with an argv array (no shell interpretation).
// Must NOT be flagged.
app.get("/greet", (req, res) => {
  const name = String(req.query.name);
  execFile("echo", ["Hello", name], (_e, stdout) => res.send(stdout));
});

export default app;
