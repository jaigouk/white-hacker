# hard-jwt-alg-confusion

- **language:** python
- **category:** AuthN/AuthZ
- **difficulty:** hard (T-12.9 headroom case)
- JWT algorithm confusion: accepting both RS256 and HS256 with the RSA public key lets an attacker forge an HS256 token signed with the public key as the HMAC secret. Benign pins a single asymmetric alg and requires exp.
