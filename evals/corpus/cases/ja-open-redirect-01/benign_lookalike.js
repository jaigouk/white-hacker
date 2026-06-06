const OK=new Set(["/home"]);
function go1(res, next){ res.redirect(OK.has(next)?next:"/home"); }
