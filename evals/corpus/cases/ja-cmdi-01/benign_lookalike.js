const cp=require("child_process");
function run1(x){ return cp.execFileSync("echo",[x]); }
