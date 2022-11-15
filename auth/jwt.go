package auth

import (
	"flag"
	"fmt"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

var (
	//jwtCAFile   = flag.String("jwt_ca_file", "", "JWT CA to trust for JWT authentication")
	jwksURL     = flag.String("jwks_url", "", "JWKS url for downloading JWT CA eg. https://domain.com/.well-known/some-provider/jwks.json")
	jwtAudience = flag.String("jwt_audience", "", "jwt audience to be verified eg. authservice.domain.com")
	jwtIssuer   = flag.String("jwt_issuer", "", "jwt issuer to be verified eg. authenticate.domain.com")
)

type jwtVerification string

func (v *jwtVerification) Username() string {
	if v != nil {
		return string(*v)
	}
	return ""
}

func (v *jwtVerification) Groups() []string {
	// Groups not used
	return []string{}
}

type jwtAuth struct {
	JWTAudience string
	JWTIssuer   string
	JWKS        *keyfunc.JWKS
}

func (o *jwtAuth) Challenge() ChallengeType {
	return ChallengeJWT
}

func (o *jwtAuth) Verify(a Attempt) (Verification, error) {
	if a.Username() != "" {
		return nil, fmt.Errorf("username should not be set")
	}
	tokenString := a.Credential()
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return o.JWKS.Keyfunc(token)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse and validate jwt")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token not valid")
	}

	if !claims.VerifyAudience(o.JWTAudience, true) {
		return nil, fmt.Errorf("claim wrong audience")
	}

	if !claims.VerifyIssuer(o.JWTIssuer, true) {
		return nil, fmt.Errorf("claim wrong issuer")
	}

	var email string
	if email, ok = claims["email"].(string); !ok {
		return nil, fmt.Errorf("claim no email")
	}
	result := jwtVerification(email)
	return &result, nil
}

func NewJWT() (*jwtAuth, error) {
	if jwksURL == nil || *jwksURL == "" {
		return nil, fmt.Errorf("jwks_url not set")
	}
	if jwtAudience == nil || *jwtAudience == "" {
		return nil, fmt.Errorf("jwt_audience not set")
	}
	if jwtIssuer == nil || *jwtIssuer == "" {
		return nil, fmt.Errorf("jwt_issuer not set")
	}
	jwks, err := keyfunc.Get(*jwksURL, keyfunc.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS from url, error: %w", err)
	}
	return &jwtAuth{
		JWTAudience: *jwtAudience,
		JWTIssuer:   *jwtIssuer,
		JWKS:        jwks,
	}, nil
}
