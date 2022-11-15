package auth

type Attempt interface {
	// Only used for username/password auth
	Username() string
	// Used for password/OTP/U2F
	Credential() string
}

type ChallengeType int

const (
	ChallengeUsernamePassword ChallengeType = 1
	ChallengeJWT              ChallengeType = 2
)

type Verification interface {
	Username() string
	Groups() []string
}
