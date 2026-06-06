const c=require("crypto");
function h2(pw){ return c.createHash("md5").update(pw).digest("hex"); }  // SINK weak-hash
