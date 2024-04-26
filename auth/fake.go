package auth

import (
	"fmt"
)

type fakeVerification struct {
	username string
	groups   []string
}

func (v *fakeVerification) Username() string {
	return v.username
}

func (v *fakeVerification) Groups() []string {
	return v.groups
}

type fakeAuth struct{}

func (l *fakeAuth) Challenge() ChallengeType {
	return ChallengeUsernamePassword
}

func (l *fakeAuth) Verify(a Attempt) (Verification, error) {
	if a.Username() == "bad" {
		return nil, fmt.Errorf("User is banned")
	}
	return &fakeVerification{
		username: a.Username(),
		groups:   []string{"fake-group", a.Username() + "-group"},
	}, nil
}

func NewFake() *fakeAuth {
	l := &fakeAuth{}
	return l
}
