const ALLOW = new Set(["api.internal"]);
async function proxy(url){
  if(!ALLOW.has(new URL(url).hostname)) throw new Error("blocked");
  return await fetch(url);
}
