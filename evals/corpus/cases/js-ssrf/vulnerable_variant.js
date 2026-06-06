async function proxy(url){
  return await fetch(url);  // SINK ssrf
}
