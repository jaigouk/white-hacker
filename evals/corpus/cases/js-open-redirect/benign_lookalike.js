const OK = new Set(["/home","/dash"]);
function go(res, next){
  res.redirect(OK.has(next) ? next : "/home");
}
