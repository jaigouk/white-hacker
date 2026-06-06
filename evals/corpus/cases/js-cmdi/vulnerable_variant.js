const cp = require("child_process");
function run(name){
  return cp.execSync(`echo ${name}`);  // SINK cmdi
}
