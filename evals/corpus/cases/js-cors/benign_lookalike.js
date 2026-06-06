const ALLOW = new Set(["https://app.example"]);
function cors(req, res){
  const o = req.headers.origin;
  if(ALLOW.has(o)){ res.set("Access-Control-Allow-Origin", o); res.set("Access-Control-Allow-Credentials","true"); }
}
