package acmelib

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"encoding/pem"

	"github.com/stugotech/golog"
	"golang.org/x/crypto/acme"
)

var logger = golog.NewPackageLogger()

const (
	// LetsEncryptLiveDirectory is the directory path to the live environment for LE.
	LetsEncryptLiveDirectory = acme.LetsEncryptURL
	// LetsEncryptStagingDirectory is the directory path to the staging environment for LE.
	// Use of this directory won't create real certificates.
	LetsEncryptStagingDirectory = "https://acme-staging.api.letsencrypt.org/directory"
)

// Client represents an acme client
type Client interface {
	// RegisterAccount creates a new user account for use with the directoy
	RegisterAccount(ctx context.Context, email string, acceptTOS bool) (*Account, error)
	// UseAccount uses the specified account for directory methods
	UseAccount(ctx context.Context, account *Account) (*Account, error)
	// CreateCertificate creates a new certificate
	CreateCertificate(ctx context.Context, domain string, san []string) (*CertificateBundle, error)
	// BeginAuthorize begins authorization on a domain by requesting the challenge
	BeginAuthorize(ctx context.Context, domain string) (*HTTPAuthChallenge, error)
	// CompleteAuthorize waits for authorization to complete on a challenge
	CompleteAuthorize(ctx context.Context, challenge AuthChallenge) error
	// CompleteAuthorizeURI waits for authorization to complete on a challenge
	CompleteAuthorizeURI(ctx context.Context, challengeURI string) error
}

// clientInfo describes the client
type clientInfo struct {
	client *acme.Client
}

// AuthChallenge describes any ACME authorization challenge
type AuthChallenge struct {
	challenge *acme.Challenge
	URI       string
}

// HTTPAuthChallenge describes an ACME http-01 challenge
type HTTPAuthChallenge struct {
	AuthChallenge
	Path     string
	Response string
}

// CertificateBundle contains the certificate chain and private key
type CertificateBundle struct {
	CertificatesRaw [][]byte
	Certificates    []*x509.Certificate
	PrivateKey      []byte
	PrivateKeyType  string
}

// Account describes a user account for use with the ACME service
type Account struct {
	URI          string
	Email        string
	Key          crypto.Signer
	KeyBytes     []byte
	CurrentTerms string
	AgreedTerms  string
}

// NewClient creates a new client connection to the ACME directory
func NewClient(directoryURL string) (Client, error) {
	logger.Debug("creating new ACME client", golog.String("directory", directoryURL))
	return &clientInfo{
		client: &acme.Client{
			DirectoryURL: directoryURL,
		},
	}, nil
}

// RegisterAccount registers the given account with the ACME service
func (c *clientInfo) RegisterAccount(ctx context.Context, email string, acceptTOS bool) (*Account, error) {
	logger.Debug("registering new account",
		golog.String("email", email),
		golog.Bool("acceptTOS", acceptTOS),
	)

	// prompt to accept the terms of service at the given URL
	prompt := func(url string) bool { return acceptTOS }

	// generate a new key for the account
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, logger.Errorex("error generating key for new account", err)
	}

	// get the raw key for easy storage
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, logger.Errorex("error marshalling key to storage", err)
	}

	// create a new client, in case everything goes wrong
	client := &acme.Client{
		DirectoryURL: c.client.DirectoryURL,
		Key:          key,
	}

	account := &acme.Account{Contact: []string{"mailto:" + email}}
	account, err = client.Register(ctx, account, prompt)

	if err != nil {
		return nil, logger.Errorex("error registering account", err, golog.String("email", email))
	}

	// things have gone well, save the new key against the client
	c.client = client

	return &Account{
		URI:          account.URI,
		Email:        email,
		AgreedTerms:  account.AgreedTerms,
		CurrentTerms: account.CurrentTerms,
		Key:          key,
		KeyBytes:     keyBytes,
	}, nil
}

// UseAccount uses the specified account for directory methods
func (c *clientInfo) UseAccount(ctx context.Context, account *Account) (*Account, error) {
	logger.Debug("using the specifed account", golog.String("email", account.Email))

	// create a new client, in case everything goes wrong
	client := &acme.Client{
		DirectoryURL: c.client.DirectoryURL,
		Key:          account.Key,
	}

	// retrieve info from server
	acc, err := client.GetReg(ctx, account.URI)
	if err != nil {
		return nil, logger.Errorex("error getting account details", err, golog.String("email", account.Email))
	}

	c.client = client

	return &Account{
		AgreedTerms:  acc.AgreedTerms,
		CurrentTerms: acc.CurrentTerms,
		Email:        account.Email,
		Key:          account.Key,
		KeyBytes:     account.KeyBytes,
		URI:          account.URI,
	}, nil
}

// BeginAuthorize begins authorization on a domain by requesting the challenge
func (c *clientInfo) BeginAuthorize(ctx context.Context, domain string) (*HTTPAuthChallenge, error) {
	// start domain authorization and get the challenge
	authz, err := c.client.Authorize(ctx, domain)
	if err != nil {
		logger.Error("error starting authorization for domain", golog.String("domain", domain))
		return nil, logger.Errore(err)
	}
	// don't need to authorize
	if authz.Status == acme.StatusValid {
		return nil, nil
	}
	// pick a challenge
	var challenge *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return nil, logger.Error("no supported challenge provided by server")
	}
	// get the response params
	challengePath := c.client.HTTP01ChallengePath(challenge.Token)
	challengeResponse, err := c.client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return &HTTPAuthChallenge{
		AuthChallenge: AuthChallenge{
			challenge: challenge,
			URI:       authz.URI,
		},
		Path:     challengePath,
		Response: challengeResponse,
	}, nil
}

// CompleteAuthorize waits for authorization to complete on a challenge
func (c *clientInfo) CompleteAuthorize(ctx context.Context, challenge AuthChallenge) error {
	_, err := c.client.Accept(ctx, challenge.challenge)
	if err != nil {
		return logger.Errore(err)
	}
	_, err = c.client.WaitAuthorization(ctx, challenge.URI)
	if err != nil {
		return logger.Errore(err)
	}
	return nil
}

// CompleteAuthorizeURI waits for authorization to complete on a challenge
func (c *clientInfo) CompleteAuthorizeURI(ctx context.Context, challengeURI string) error {
	challenge, err := c.client.GetChallenge(ctx, challengeURI)
	if err != nil {
		return logger.Errore(err)
	}
	_, err = c.client.Accept(ctx, challenge)
	if err != nil {
		return logger.Errore(err)
	}
	_, err = c.client.WaitAuthorization(ctx, challenge.URI)
	if err != nil {
		return logger.Errore(err)
	}
	return nil
}

// CreateCertificate creates a new certificate
func (c *clientInfo) CreateCertificate(ctx context.Context, domain string, san []string) (*CertificateBundle, error) {
	// generate key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, logger.Errore(err)
	}
	// encode key
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, logger.Errore(err)
	}
	// create csr
	csr, err := certRequest(key, domain, san)
	if err != nil {
		return nil, logger.Errore(err)
	}
	// get cert from ACME server
	der, _, err := c.client.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return nil, logger.Errore(err)
	}
	// parse cert bundle
	bundle, err := parseCertificates(der)
	if err != nil {
		return nil, logger.Errore(err)
	}
	// validate bundle and return leaf cert
	err = validateCertificateChain(domain, bundle, key)
	if err != nil {
		return nil, logger.Errore(err)
	}
	return &CertificateBundle{
		CertificatesRaw: der,
		Certificates:    bundle,
		PrivateKey:      keyBytes,
		PrivateKeyType:  "EC",
	}, nil
}

// CertificatesPEM encodes the certificates to PEM format
func (c *CertificateBundle) CertificatesPEM() []byte {
	var buf []byte

	for _, cert := range c.CertificatesRaw {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}
		buf = append(buf, pem.EncodeToMemory(&block)...)
	}

	return buf
}

// PrivateKeyPEM encodes the private key to PEM format
func (c *CertificateBundle) PrivateKeyPEM() []byte {
	block := pem.Block{
		Type:  c.PrivateKeyType + " PRIVATE KEY",
		Bytes: c.PrivateKey,
	}
	return pem.EncodeToMemory(&block)
}

// parseCertificates parses a DER-encoded certificate bundle into a slice of X509 Certificates
func parseCertificates(der [][]byte) ([]*x509.Certificate, error) {
	var err error
	certs := make([]*x509.Certificate, len(der))
	for i, c := range der {
		certs[i], err = x509.ParseCertificate(c)
		if err != nil {
			return nil, err
		}
	}
	return certs, nil
}

// certRequest creates a certificate request for the given common name cn and optional SANs.
func certRequest(key crypto.Signer, cn string, san []string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: san,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

// validateCertificateChain parses a cert chain provided as der argument and verifies the leaf, der[0],
// corresponds to the private key, as well as the domain match and expiration dates.
// It doesn't do any revocation checking.
//
// The returned value is the verified leaf cert.
func validateCertificateChain(domain string, bundle []*x509.Certificate, key crypto.Signer) error {
	// verify the leaf is not expired and matches the domain name
	leaf := bundle[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return logger.Error("certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return logger.Error("expired certificate")
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return err
	}
	// ensure the leaf corresponds to the private key
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return logger.Error("private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return logger.Error("private key does not match public key")
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return logger.Error("private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return logger.Error("private key does not match public key")
		}
	default:
		return logger.Error("unknown public key algorithm")
	}
	return nil
}
