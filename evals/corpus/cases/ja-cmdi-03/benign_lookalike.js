const cp=require("child_process");
function run3(x){ return cp.execFileSync("echo",[x]); }
