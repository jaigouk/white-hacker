const OK=new Set(["/home"]);
function go4(res, next){ res.redirect(OK.has(next)?next:"/home"); }
