package webui

import (
	"fmt"
	"log"

	pb "github.com/baffinbay/proto/auth"
	"github.com/baffinbay/authservice/auth"
	"github.com/baffinbay/authservice/verify"
	"github.com/google/uuid"
)

type loginSession struct {
	p *webuiServer
	// Structured attempt queue
	atq chan auth.Attempt
	// Redirect queue
	rq chan string
	// Attempt error queue
	eq chan error

	// On the first request this cookie is set to pin the session to a single
	// browser. Attempting to set this twice will fail.
	cookie string

	id           string
	Request      *pb.UserCredentialRequest
	NextUrl      string
	Page         string
	VerifiedUser *pb.VerifiedUser
}

type attempt struct {
	username   string
	credential string
}

func (a *attempt) Username() string {
	return a.username
}

func (a *attempt) Credential() string {
	return a.credential
}

func (s *webuiServer) NewSession(r *pb.UserCredentialRequest, atq chan auth.Attempt, eq chan error) verify.Session {
	id := uuid.New().String()
	rq := make(chan string, 0)
	sess := &loginSession{
		Request: r,
		NextUrl: fmt.Sprintf("/next?session=%s", id),
		id:      id,
		eq:      eq,
		atq:     atq,
		rq:      rq,
		p:       s,
	}
	s.sessionLock.Lock()
	s.sessions[id] = sess
	s.sessionLock.Unlock()
	return sess
}

func (s *loginSession) ChallengeLogin() *pb.UserAction {
	return &pb.UserAction{Url: fmt.Sprintf("/login?session=%s", s.id)}
}

func (s *loginSession) ChallengeJWT() *pb.UserAction {
	return &pb.UserAction{Url: fmt.Sprintf("/jwt?session=%s", s.id)}
}

func (s *loginSession) ChallengeReview(u *pb.VerifiedUser) *pb.UserAction {
	s.VerifiedUser = u
	s.rq <- fmt.Sprintf("/review?session=%s", s.id)
	return nil
}

func (s *loginSession) ChallengeComplete() *pb.UserAction {
	s.rq <- fmt.Sprintf("/complete?session=%s", s.id)
	return nil
}

func (s *loginSession) ChallengeError() *pb.UserAction {
	s.rq <- fmt.Sprintf("/error")
	return nil
}

func (s *loginSession) sendAttempt(a *attempt) error {
	select {
	case s.atq <- a:
		return <-s.eq
	default:
		return fmt.Errorf("Session is gone")
	}

}

func (s *loginSession) ProcessLogin(username string, password string) error {
	return s.sendAttempt(&attempt{username, password})
}

func (s *loginSession) ProcessJWT(token string) error {
	return s.sendAttempt(&attempt{"", token})
}

func (s *loginSession) ProcessReview() error {
	return s.sendAttempt(&attempt{})
}

func (s *loginSession) ProcessComplete() error {
	return s.sendAttempt(&attempt{})
}

func (s *loginSession) ProcessError() error {
	return s.sendAttempt(&attempt{})
}

func (s *loginSession) NextStep() string {
	return <-s.rq
}

func (s *loginSession) Cookie() (string, error) {
	if s.cookie != "" {
		return "", fmt.Errorf("cookie already set")
	}
	s.cookie = uuid.New().String()
	return s.cookie, nil
}

func (s *loginSession) VerifyCookie(c string) bool {
	return s.cookie == c && s.cookie != ""
}

func (s *loginSession) Close() {
	close(s.rq)
}

func (s *loginSession) Destroy() {
	s.p.sessionLock.Lock()
	delete(s.p.sessions, s.id)
	s.p.sessionLock.Unlock()
	close(s.rq)
	log.Printf("Cleaned up session %s", s.id)
}
