package main

import (
	"flag"
	"log"
	"net"

	"github.com/baffinbay/authservice/audit"
	"github.com/baffinbay/authservice/auth"
	"github.com/baffinbay/authservice/rpc"
	"github.com/baffinbay/authservice/sign"
	"github.com/baffinbay/authservice/verify"
	"github.com/baffinbay/authservice/webui"
	"github.com/soheilhy/cmux"
)

var (
	listenAddress = flag.String("listen", ":1214", "Address to listen to")
	login         = flag.String("login", "ldap", "Login method to use")
)

func main() {
	flag.Parse()

	s, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	mux := cmux.New(s)
	sg := mux.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))
	sh := mux.Match(cmux.Any())

	a := audit.New()
	si := sign.New(a)
	w := webui.New()
	var ab verify.AuthBackend
	if *login == "ldap" {
		ab = auth.NewLDAP()
	} else if *login == "jwt" {
		ab, err = auth.NewJWT()
		if err != nil {
			panic(err)
		}
	} else if *login == "fake" {
		ab = auth.NewFake()
	}
	v := verify.New(w, si, ab)
	r := rpc.New(v)

	go r.Serve(sg)
	go w.Serve(sh)

	err = mux.Serve()
	if err != nil {
		log.Fatalf("failed to serve mux: %v", err)
	}
}
