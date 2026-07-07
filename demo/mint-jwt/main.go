// mint-jwt — mints a short-lived HS256 JWT for the IDOR demo (sub + roles),
// compatible with the gateway's HMAC auth mode. Demo helper, not production.
package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	secret := flag.String("secret", "", "HMAC secret (same as AEGIS_JWT_SECRET)")
	sub := flag.String("sub", "", "subject / user id")
	roles := flag.String("roles", "user", "comma-separated roles")
	ttl := flag.Duration("ttl", time.Hour, "token lifetime")
	flag.Parse()

	var rs []string
	for _, r := range strings.Split(*roles, ",") {
		if r = strings.TrimSpace(r); r != "" {
			rs = append(rs, r)
		}
	}
	claims := jwt.MapClaims{
		"sub":   *sub,
		"roles": rs,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(*ttl).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(*secret))
	if err != nil {
		panic(err)
	}
	fmt.Print(tok)
}
