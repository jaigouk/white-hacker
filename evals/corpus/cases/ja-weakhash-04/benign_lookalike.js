const b=require("bcrypt");
function h4(pw){ return b.hashSync(pw,12); }
