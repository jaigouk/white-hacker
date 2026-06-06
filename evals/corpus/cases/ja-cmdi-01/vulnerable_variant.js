const cp=require("child_process");
function run1(x){ return cp.execSync("echo "+x); }  // SINK cmdi
