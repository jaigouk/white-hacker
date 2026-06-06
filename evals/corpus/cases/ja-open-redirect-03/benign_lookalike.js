const OK=new Set(["/home"]);
function go3(res, next){ res.redirect(OK.has(next)?next:"/home"); }
