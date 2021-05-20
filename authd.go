package main

import (
	"flag"
	"log"
	"net"

	"github.com/cockroachdb/cmux"
	"github.com/elastx/authservice/audit"
	"github.com/elastx/authservice/auth"
	"github.com/elastx/authservice/rpc"
	"github.com/elastx/authservice/sign"
	"github.com/elastx/authservice/verify"
	"github.com/elastx/authservice/webui"
)

var (
	listenAddress = flag.String("listen", ":1214", "Address to listen to")
)

func main() {
	flag.Parse()

	s, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	mux := cmux.New(s)
	sg := mux.Match(cmux.HTTP2HeaderField("content-type", "application/grpc"))
	sh := mux.Match(cmux.Any())

	a := audit.New()
	si := sign.New(a)
	w := webui.New()
	ldap := auth.NewLDAP()
	v := verify.New(w, si, ldap)
	r := rpc.New(v)

	go r.Serve(sg)
	go w.Serve(sh)

	err = mux.Serve()
	if err != nil {
		log.Fatalf("failed to serve mux: %v", err)
	}
}
