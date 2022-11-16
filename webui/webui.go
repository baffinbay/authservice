package webui

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"
)

var (
	secureCookie = flag.Bool("secure_cookie", true, "Whether or not to mark the session cookie for only HTTPS use")
	jwt_header   = flag.String("jwt_header", "X-Jwt-Assertion", "Header that should contain the jwt")
)

type webuiServer struct {
	completeTmpl *template.Template
	loginTmpl    *template.Template
	reviewTmpl   *template.Template
	errorTmpl    *template.Template
	sessionLock  *sync.Mutex
	sessions     map[string]*loginSession
}

func (s *webuiServer) handleLogin(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderLogin(sess, w, r)
	}
	if r.Method == "POST" {
		s.processLogin(sess, w, r)
	}
}

func (s *webuiServer) processLogin(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username, ok := r.PostForm["username"]
	if !ok {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}
	password, ok := r.PostForm["password"]
	if !ok {
		http.Error(w, "No password provided", http.StatusBadRequest)
		return
	}

	err := sess.ProcessLogin(username[0], password[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	log.Printf("User %v login challenge successful", username[0])
}

func (s *webuiServer) renderLogin(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/html;charset=utf-8")
	log.Printf("Rendering login")
	err := s.loginTmpl.Execute(w, sess)
	if err != nil {
		log.Printf("error when rendering login template: %v", err)
	}
}

func (s *webuiServer) handleJWT(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/plain")

	tokens := r.Header[*jwt_header]
	if len(tokens) != 1 {
		http.Error(w, "auth failed, no jwt", http.StatusUnauthorized)
		log.Printf("auth failed, no jwt")
		return
	}

	err := sess.ProcessJWT(tokens[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	s.renderReview(sess, w, r)
}

func (s *webuiServer) handleNext(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/plain")
	w.Write([]byte(sess.NextStep()))
}

func (s *webuiServer) handleReview(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderReview(sess, w, r)
	}
	if r.Method == "POST" {
		s.processReview(sess, w, r)
	}
}

func (s *webuiServer) renderReview(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/html;charset=utf-8")
	err := s.reviewTmpl.Execute(w, sess)
	if err != nil {
		log.Printf("error when rendering review template: %v", err)
	}
}

func (s *webuiServer) processReview(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	err := sess.ProcessReview()
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	log.Printf("Review challenge successful")
}

func (s *webuiServer) handleComplete(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/html;charset=utf-8")
	err := s.completeTmpl.Execute(w, nil)
	if err != nil {
		log.Printf("error when rendering complete template: %v", err)
	}
	sess.ProcessComplete()
}

func (s *webuiServer) handleError(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/html;charset=utf-8")
	err := s.errorTmpl.Execute(w, nil)
	if err != nil {
		log.Printf("error when rendering error template: %v", err)
	}
}

func (s *webuiServer) withSession(rh func(*loginSession, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, ok := r.URL.Query()["session"]
		if !ok {
			http.Error(w, "No session ID provided", http.StatusBadRequest)
			return
		}
		session, ok := s.sessions[sid[0]]
		if !ok {
			http.Error(w, "Invalid session ID provided", http.StatusBadRequest)
			return
		}
		// On the first request, generate a secret cookie to verify session progress
		c, err := r.Cookie("Auth-Session-Secret")
		if err == nil {
			if !session.VerifyCookie(c.Value) {
				err = fmt.Errorf("failed to validate cookie")
			}
		}
		if err != nil {
			secret, err := session.Cookie()
			if err != nil {
				log.Printf("Tried to set cookie twice, probably something bad going on - rejecting request")
				http.Error(w, "No session cookie", http.StatusBadRequest)
				return
			}

			c := &http.Cookie{
				Name:   "Auth-Session-Secret",
				Value:  secret,
				Path:   "/",
				Secure: *secureCookie,
			}
			http.SetCookie(w, c)
		}
		rh(session, w, r)
	}
}

func (s *webuiServer) Serve(l net.Listener) {
	m := http.NewServeMux()
	m.HandleFunc("/login", s.withSession(s.handleLogin))
	m.HandleFunc("/jwt", s.withSession(s.handleJWT))
	m.HandleFunc("/next", s.withSession(s.handleNext))
	m.HandleFunc("/review", s.withSession(s.handleReview))
	m.HandleFunc("/complete", s.withSession(s.handleComplete))
	m.HandleFunc("/error", s.handleError)
	http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("HTTP: %s %s", r.Method, r.URL)
		m.ServeHTTP(w, r)
	}))
}

func New() *webuiServer {
	s := new(webuiServer)
	s.completeTmpl = template.Must(template.ParseFiles("tmpl/site.tmpl", "tmpl/no-validate.tmpl", "tmpl/complete.tmpl"))
	s.loginTmpl = template.Must(template.ParseFiles("tmpl/site.tmpl", "tmpl/validate.tmpl", "tmpl/login.tmpl"))
	s.reviewTmpl = template.Must(template.ParseFiles("tmpl/site.tmpl", "tmpl/validate.tmpl", "tmpl/review.tmpl"))
	s.errorTmpl = template.Must(template.ParseFiles("tmpl/site.tmpl", "tmpl/no-validate.tmpl", "tmpl/error.tmpl"))
	s.sessions = make(map[string]*loginSession)
	s.sessionLock = &sync.Mutex{}
	return s
}
