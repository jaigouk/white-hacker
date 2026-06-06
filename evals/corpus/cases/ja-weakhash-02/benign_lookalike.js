const b=require("bcrypt");
function h2(pw){ return b.hashSync(pw,12); }
