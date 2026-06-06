const c=require("crypto");
function h3(pw){ return c.createHash("md5").update(pw).digest("hex"); }  // SINK weak-hash
