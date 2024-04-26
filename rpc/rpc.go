package rpc

import (
	"log"
	"net"

	pb "github.com/baffinbay/proto/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
)

type Verifier interface {
	VerifyAndSign(
		*pb.UserCredentialRequest,
		chan *pb.UserAction,
		*pb.VerifiedUser,
	) (*pb.CredentialResponse, error)
}

type authServer struct {
	verifier Verifier
}

func (s *authServer) RequestUserCredential(
	r *pb.UserCredentialRequest,
	stream pb.AuthenticationService_RequestUserCredentialServer,
) error {
	log.Printf("Handling request %v", *r)
	aq := make(chan *pb.UserAction, 1)
	go func() {
		// As long as the validator sends user actions, pass them along.
		for action := range aq {
			stream.Send(&pb.CredentialResponse{
				RequiredAction: action,
			})
		}
	}()

	p, _ := peer.FromContext(stream.Context())
	ip, port, _ := net.SplitHostPort(p.Addr.String())
	user := pb.VerifiedUser{Ip: ip, Port: port, ReverseDns: "unknown"}

	rdns, err := net.LookupAddr(ip)
	if err == nil {
		user.ReverseDns = rdns[0]
	}

	res, err := s.verifier.VerifyAndSign(r, aq, &user)
	if err != nil {
		log.Printf("User failed validation: %v", err)
		return err
	}
	stream.Send(res)
	log.Printf("Response sent")
	return nil
}

func (s *authServer) Serve(l net.Listener) {
	g := grpc.NewServer()
	pb.RegisterAuthenticationServiceServer(g, s)
	reflection.Register(g)
	g.Serve(l)
}

func New(verifier Verifier) *authServer {
	s := new(authServer)
	s.verifier = verifier
	return s
}
