package sign

import (
	"fmt"
	"strings"

	pb "github.com/dhtech/proto/auth"
	vault "github.com/hashicorp/vault/api"
)

type Auditor interface {
	Log(string)
}

type signer struct {
	a Auditor
	v *vault.Client
	gmap map[string]string
}

func (s *signer) Sign(r *pb.UserCredentialRequest, u *pb.VerifiedUser) (*pb.CredentialResponse, error) {
	res := &pb.CredentialResponse{}

	// TODO(bluecmd): Refactor this
	artifacts := make([]string, 0)
	if r.SshCertificateRequest != nil {
		a, err := s.signSsh(r, u, res)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, a)
	}

	if r.VaultTokenRequest != nil {
		a, err := s.signVault(r, u, res)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, a)
	}

	if r.KubernetesCertificateRequest != nil {
		a, err := s.signKubernetes(r, u, res)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, a)
	}

	if r.BrowserCertificateRequest != nil {
		a, err := s.signBrowser(r, u, res)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, a)
	}

	if r.VmwareCertificateRequest != nil {
		a, err := s.signVmware(r, u, res)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, a)
	}

	s.a.Log(fmt.Sprintf("signed %s for %s", strings.Join(artifacts, ", "), u.Username))
	return res, nil
}

func New(a Auditor) *signer {
	s := &signer{
		a: a,
	}
	s.initVault()
	return s
}
