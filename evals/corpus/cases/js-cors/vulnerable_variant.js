function cors(req, res){
  res.set("Access-Control-Allow-Origin", req.headers.origin);  // SINK cors-reflect
  res.set("Access-Control-Allow-Credentials", "true");
}
