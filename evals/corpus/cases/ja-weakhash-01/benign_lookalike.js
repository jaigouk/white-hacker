const b=require("bcrypt");
function h1(pw){ return b.hashSync(pw,12); }
