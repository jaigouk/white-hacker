const cp=require("child_process");
function run2(x){ return cp.execSync("echo "+x); }  // SINK cmdi
