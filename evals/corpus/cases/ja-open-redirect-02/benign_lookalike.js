const OK=new Set(["/home"]);
function go2(res, next){ res.redirect(OK.has(next)?next:"/home"); }
