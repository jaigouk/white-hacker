import jwt from "jsonwebtoken";
export function check(t: string, k: string){
  return jwt.verify(t, k, { algorithms: ["RS256"] });
}
