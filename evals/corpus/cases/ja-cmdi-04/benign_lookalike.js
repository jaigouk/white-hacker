const cp=require("child_process");
function run4(x){ return cp.execFileSync("echo",[x]); }
