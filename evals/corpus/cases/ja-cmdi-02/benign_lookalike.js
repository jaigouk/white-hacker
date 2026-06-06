const cp=require("child_process");
function run2(x){ return cp.execFileSync("echo",[x]); }
