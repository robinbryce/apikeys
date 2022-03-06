# apikeys

A scheme for oauth2 client_credentials compatible api keys.

## Secret generation
* Use [argon2id](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id). As per "other applications" on [rfc2898](https://www.ietf.org/rfc/rfc2898.txt) [go implementation](https://pkg.go.dev/golang.org/x/crypto/argon2)
* TODO: if FIPS-140 is required use [pkkdf2](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2). As per "[go implementation](https://pkg.go.dev/golang.org/x/crypto/pbkdf2)

Recomendations taken from [here](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
