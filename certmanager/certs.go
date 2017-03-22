package certmanager

import (
	"context"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/stugotech/goconfig"
	"github.com/stugotech/golog"
	"github.com/stugotech/superproxy/acmelib"
	"github.com/stugotech/superproxy/cryptex"
	"github.com/stugotech/superproxy/store"
	"github.com/stugotech/superproxy/store/libkv"
	"github.com/stugotech/superproxy/store/secret"
)

var logger = golog.NewPackageLogger()

const (
	authRetries = 5
	backoffMs   = 300
)

// configuration keys
const (
	AcceptTOSKey     = "accept-tos"
	AcmeDirectoryKey = "acme-directory"
	EmailKey         = "email"
)

// CertificateManager deals with issuing and renewing certificates.
type CertificateManager interface {
	// EnsureCertificate creates a certificate for the specified domain if it doesn't already exist.
	EnsureCertificate(domain string, certificateSubject string) (*store.Certificate, error)
	// RenewExpiringCertificates checks expiry dates on certificates and renews certificates that will
	// expire before `before` has elapsed.
	RenewExpiringCertificates(before time.Duration) ([]*store.Certificate, error)
}

// certManager is an implementation of CertificateManager.
type certManager struct {
	email     string
	directory string
	acceptTOS bool
	secretbox secret.Box
	client    acmelib.Client
	store     store.Store
}

// NewCertificateManager creates a new instance of CertificateManager from the given config.
func NewCertificateManager(cfg goconfig.Config) (CertificateManager, error) {
	// config
	c := &certManager{
		email:     cfg.GetString(EmailKey),
		directory: cfg.GetString(AcmeDirectoryKey),
		acceptTOS: cfg.GetBool(AcceptTOSKey),
	}

	if c.email == "" || c.directory == "" {
		return nil, logger.Error("must specify email address and directory URL")
	}

	// set up encryption
	var err error
	c.secretbox, err = secret.NewBoxFromConfig(cfg)
	if err != nil {
		return nil, logger.Errore(err)
	}

	// set up store
	c.store, err = libkv.NewStoreFromConfig(cfg)
	if err != nil {
		return nil, logger.Errore(err)
	}

	// create ACME client
	c.client, err = acmelib.NewClient(c.directory)
	if err != nil {
		return nil, logger.Errore(err)
	}

	// authenticate ACME client
	account, err := c.getAccount(c.email)
	if err != nil {
		return nil, logger.Errore(err)
	}

	if account != nil {
		_, err = c.client.UseAccount(context.Background(), account)
		if err != nil {
			return nil, logger.Errore(err)
		}
	} else {
		// no account found - create new account
		account, err = c.createAccount(c.email, c.acceptTOS)
		if err != nil {
			return nil, logger.Errore(err)
		}
	}

	return c, nil
}

// EnsureCertificate creates a single certificate
func (c *certManager) EnsureCertificate(domain string, certificateSubject string) (*store.Certificate, error) {
	var sans []string
	var err error

	if certificateSubject == "" {
		certificateSubject, err = publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return nil, logger.Errorex("can't get public suffix for domain", err, golog.String("domain", domain))
		}
	}
	if certificateSubject != domain {
		sans = append(sans, domain)
	}
	cert, err := c.addCertificate(certificateSubject, sans, false)
	if err != nil {
		return nil, logger.Errore(err)
	}
	return cert, nil
}

// RenewExpiringCertificates checks expiry dates on certificates and renews certificates that will
// expire before `before` has elapsed.
func (c *certManager) RenewExpiringCertificates(before time.Duration) ([]*store.Certificate, error) {
	certs, err := c.store.GetCertificates()
	if err != nil {
		return nil, logger.Errore(err)
	}

	var renewedCerts []*store.Certificate
	threshold := time.Now().Add(before)

	for _, cert := range certs {
		if threshold.After(cert.Expires) {
			newCert, err := c.addCertificate(cert.Subject, cert.AlternativeNames, true)
			if err != nil {
				return nil, logger.Errore(err)
			}
			renewedCerts = append(renewedCerts, newCert)
		}
	}

	return renewedCerts, nil
}

// AuthorizeAll runs authorization on all of the domains.
func (c *certManager) AuthorizeAll(domains []string) error {
	for _, domain := range domains {
		err := c.Authorize(domain)
		if err != nil {
			return err
		}
	}
	return nil
}

// Authorize runs authorization on the given domain
func (c *certManager) Authorize(domain string) error {
	challenge, err := c.BeginAuthorize(domain)
	if err != nil {
		return logger.Errore(err)
	}
	if challenge == nil {
		// no authorisation required
		return nil
	}

	ctx := context.Background()

	for i := 1; ; i++ {
		err = c.client.CompleteAuthorize(ctx, challenge.AuthChallenge)
		if err == nil {
			break
		}
		if i >= authRetries {
			return err
		}
		// wait a bit before trying again
		time.Sleep(time.Duration(i*backoffMs) * time.Millisecond)
	}

	logger.Info("authorization of domain successful", golog.String("domain", domain))
	return nil
}

// BeginAuthorize gets the challenge details for the given domain
func (c *certManager) BeginAuthorize(domain string) (*acmelib.HTTPAuthChallenge, error) {
	logger.Info("begin authorization of domain", golog.String("domain", domain))
	ctx := context.Background()

	challenge, err := c.client.BeginAuthorize(ctx, domain)
	if err != nil {
		return nil, logger.Errore(err)
	}

	if challenge == nil {
		logger.Debug("no authorization required", golog.String("domain", domain))
		return nil, nil
	}

	logger.Debug("challenge received",
		golog.String("URI", challenge.URI),
		golog.String("path", challenge.Path),
		golog.String("response", challenge.Response),
	)

	host, err := c.store.GetHost(domain)
	if err != nil {
		return nil, logger.Errore(err)
	}

	if host == nil {
		host = &store.Host{
			Host: domain,
		}
	}

	host.ACMEChallenge.ChallengePath = challenge.Path
	host.ACMEChallenge.Response = challenge.Response

	err = c.store.PutHost(host)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return challenge, nil
}

// getAccount looks up the account and returns the key if it exists
func (c *certManager) getAccount(email string) (*acmelib.Account, error) {
	account, err := c.store.GetACMEAccount(email)
	if err != nil {
		return nil, logger.Errore(err)
	}
	if account == nil {
		return nil, nil
	}
	key, err := c.secretbox.Open(account.Key)
	if err != nil {
		return nil, logger.Errore(err)
	}
	signer, err := cryptex.ParsePrivateKeyFromDER(key)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return &acmelib.Account{
		URI:   account.URI,
		Key:   signer,
		Email: account.Email,
	}, nil
}

// createAccount creates a new account
func (c *certManager) createAccount(email string, acceptTOS bool) (*acmelib.Account, error) {
	account, err := c.client.RegisterAccount(context.Background(), email, acceptTOS)
	if err != nil {
		return nil, logger.Errorex("error creating new account", err, golog.String("email", email))
	}
	// encrypt key
	keyBytes, err := c.secretbox.Seal(account.KeyBytes)
	if err != nil {
		return nil, logger.Errore(err)
	}
	// save new account
	storeAccount := &store.ACMEAccount{
		URI:   account.URI,
		Email: email,
		Key:   keyBytes,
	}
	err = c.store.PutACMEAccount(storeAccount)
	if err != nil {
		return nil, logger.Errore(err)
	}
	return account, nil
}

// addCertificate does the actual work in adding a certificate.
func (c *certManager) addCertificate(domain string, sans []string, renew bool) (*store.Certificate, error) {
	// see if the domain already has a certificate
	storeCert, err := c.store.GetCertificate(domain)
	if err != nil {
		return nil, logger.Errore(err)
	}

	if storeCert != nil {
		newSans := diffStrings(storeCert.AlternativeNames, sans)

		if !renew && len(newSans) == 0 {
			logger.Debug("already have certificate",
				golog.String("domain", domain),
				golog.Strings("sans", sans),
			)
			return storeCert, nil
		}

		// add new sans to the existing list for renewal
		sans = append(sans, newSans...)
	}

	// creating new cert, so authorize all the domains first
	authList := make([]string, len(sans)+1)
	copy(authList, sans)
	authList[len(sans)] = domain

	err = c.AuthorizeAll(authList)
	if err != nil {
		return nil, logger.Errore(err)
	}

	// create the cert
	cert, err := c.client.CreateCertificate(context.Background(), domain, sans)
	if err != nil {
		return nil, logger.Errore(err)
	}

	// encrypt private key
	key, err := c.secretbox.Seal(cert.PrivateKeyPEM())
	if err != nil {
		return nil, logger.Errore(err)
	}

	storeCert = &store.Certificate{
		Subject:          domain,
		AlternativeNames: sans,
		CertificateChain: cert.CertificatesPEM(),
		PrivateKey:       key,
		Expires:          cert.Certificates[0].NotAfter,
	}

	err = c.store.PutCertificate(storeCert)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return storeCert, nil
}

// diffStrings returns the unique strings in all of the lists which aren't in the first
func diffStrings(src ...[]string) []string {
	first := make(map[string]struct{})
	unique := make(map[string]struct{})

	for i, srci := range src {
		for _, v := range srci {
			if i == 0 {
				first[v] = struct{}{}
			} else {
				if _, ok := first[v]; !ok {
					unique[v] = struct{}{}
				}
			}
		}
	}

	keys := make([]string, len(unique))
	i := 0

	for k := range unique {
		keys[i] = k
		i++
	}

	return keys
}
