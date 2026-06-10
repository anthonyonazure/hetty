package jwt

// WeakSecrets is a small built-in list of HMAC secrets commonly left in place
// by misconfigured JWT implementations. Users can supply a larger list.
var WeakSecrets = []string{
	"secret", "password", "123456", "changeme", "admin", "jwt", "jwtsecret",
	"your-256-bit-secret", "your_jwt_secret", "supersecret", "secretkey",
	"mysecret", "test", "key", "private", "token", "auth", "default",
	"qwerty", "letmein", "hello", "root", "toor", "pass", "0000", "1234",
	"s3cr3t", "secret123", "P@ssw0rd", "iloveyou", "welcome", "ChangeMe!",
	"HS256", "JWTSecretKey", "node-jsonwebtoken", "express-jwt", "keyboard cat",
}
