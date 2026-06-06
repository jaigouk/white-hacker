const cp=require("child_process");
function run3(x){ return cp.execSync("echo "+x); }  // SINK cmdi
