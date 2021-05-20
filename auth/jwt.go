package auth

import (
	"flag"
)

var (
	jwtCAFile = flag.String("jwt_ca_file", "jwt.ca.pem", "JWT CA to trust for JWT authentication")
)

type jwtAuth struct {
}

func (l *jwtAuth) Challenge() ChallengeType {
	return ChallengeJWT
}

func (l *jwtAuth) Verify(a Attempt) ([]string, error) {
	return []string{"jwt-group"}, nil
}

func NewJWT() *jwtAuth {
	l := &jwtAuth{}
	return l
}
