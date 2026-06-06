const OK=new Set(["api.internal"]);
async function fetch1(u){ if(!OK.has(new URL(u).hostname)) throw new Error("x"); return await fetch(u); }
