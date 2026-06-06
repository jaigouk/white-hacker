const b=require("bcrypt");
function h3(pw){ return b.hashSync(pw,12); }
