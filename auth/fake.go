package auth

import (
	"fmt"
)

type fakeAuth struct {
}

func (l *fakeAuth) Challenge() ChallengeType {
	return ChallengeUsernamePassword
}

func (l *fakeAuth) Verify(a Attempt) ([]string, error) {
	if a.Username() == "bad" {
		return nil, fmt.Errorf("User is banned")
	}
	return []string{"fake-group", a.Username() + "-group"}, nil
}

func NewFake() *fakeAuth {
	l := &fakeAuth{}
	return l
}
