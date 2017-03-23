package store

import (
	"fmt"
	"time"

	"crypto/tls"

	"crypto"

	"github.com/stugotech/golog"
	"github.com/stugotech/superproxy/store/secret"
)

var logger = golog.NewPackageLogger()

// Store allows data to be retrieved from an arbitrary store.
type Store interface {
	GetACMEAccount(email string) (*ACMEAccount, error)
	GetCertificate(subject string) (*Certificate, error)
	GetHost(host string) (*Host, error)

	PutACMEAccount(account *ACMEAccount) error
	PutCertificate(cert *Certificate) error
	PutHost(host *Host) error

	RemoveHost(host string) error
	RemoveCertificate(subject string) error

	GetCertificates() ([]*Certificate, error)
	GetHosts() ([]*Host, error)

	WatchCertificates(stop <-chan struct{}) (<-chan []*Certificate, error)
	WatchHosts(stop <-chan struct{}) (<-chan []*Host, error)
}

// SecurityMode represents the security behaviour of a front end.
type SecurityMode int

// The following values are valid for SecurityMode:
const (
	// UnsecureOnly means that the front end will only support connections on HTTP.
	UnsecureOnly SecurityMode = iota
	// SecureOnly means that the front end will only support connections on HTTPS.
	SecureOnly
	// SecureAndUnsecure means that the front end will support connections on both HTTPS and HTTP.
	SecureAndUnsecure
	// UpgradeSecurity means that the front end will redirect HTTP connections to HTTPS.
	UpgradeSecurity
)

// string values for security modes
const (
	UnsecureOnlyStr      = "unsecure"
	SecureOnlyStr        = "secure"
	SecureAndUnsecureStr = "both"
	UpgradeSecurityStr   = "upgrade"
)

// Configuration keys
const (
	StoreKey       = "store"
	StoreNodesKey  = "store-nodes"
	StorePrefixKey = "store-prefix"
)

// ACMEAccount represents a user account on an ACME directory
type ACMEAccount struct {
	URI   string
	Email string
	Key   []byte
}

// Host represents an available website.
type Host struct {
	Host               string        // the Host header value for incoming connections
	CertificateSubject string        // the subject domain for the certificate used
	Security           SecurityMode  // HTTP/HTTPS behaviour for incoming connections
	ProxyTo            string        // the authority to forward requests to
	ACMEChallenge      ACMEChallenge // the ACME challenge data
}

// ACMEChallenge stores info about an ACME authorization challenge.
type ACMEChallenge struct {
	ChallengePath string
	Response      string
}

// Certificate represents a certificate used on a server
type Certificate struct {
	Subject          string
	AlternativeNames []string
	Expires          time.Time
	CertificateChain []byte
	PrivateKey       []byte
}

// DecodeCertificate returns the decoded x509 certificate.
func (c *Certificate) DecodeCertificate(box secret.Box) (*tls.Certificate, error) {
	key, err := box.Open(c.PrivateKey)
	if err != nil {
		return nil, logger.Errorex("can't unseal certificate key", err)
	}

	cert, err := tls.X509KeyPair(c.CertificateChain, key)
	if err != nil {
		return nil, logger.Errorex("can't decode certificate", err)
	}

	return &cert, nil
}

// DecodeKey gets the key for the account.
func (a *ACMEAccount) DecodeKey(box secret.Box) (crypto.Signer, error) {
	key, err := box.Open(a.Key)
	if err != nil {
		return nil, logger.Errorex("can't unseal account key", err)
	}

	s, err := parsePrivateKeyFromDER(key)
	if err != nil {
		return nil, logger.Errorex("can't parse account key", err)
	}

	return s, nil
}

// ParseSecurityMode translates a string into a SecurityMode.
func ParseSecurityMode(mode string) (SecurityMode, error) {
	switch mode {
	case UnsecureOnlyStr:
		return UnsecureOnly, nil
	case SecureOnlyStr:
		return SecureOnly, nil
	case SecureAndUnsecureStr:
		return SecureAndUnsecure, nil
	case UpgradeSecurityStr:
		return UpgradeSecurity, nil
	default:
		return 0, logger.Error("invalid security mode", golog.String("value", mode))
	}
}

// String translates a SecurityMode into a string.
func (s SecurityMode) String() string {
	switch s {
	case UnsecureOnly:
		return UnsecureOnlyStr
	case SecureOnly:
		return SecureOnlyStr
	case SecureAndUnsecure:
		return SecureAndUnsecureStr
	case UpgradeSecurity:
		return UpgradeSecurityStr
	default:
		panic(fmt.Sprintf("invalid security mode value %d", int(s)))
	}
}
