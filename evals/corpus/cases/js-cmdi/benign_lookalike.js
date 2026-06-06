const cp = require("child_process");
function run(name){
  return cp.execFileSync("echo", [name]);
}
