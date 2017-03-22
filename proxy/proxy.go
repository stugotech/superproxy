package proxy

import (
	"crypto/tls"
	"sync"

	"net/http"

	"net/http/httputil"

	"os"

	"github.com/stugotech/goconfig"
	"github.com/stugotech/golog"
	"github.com/stugotech/superproxy/store"
	"github.com/stugotech/superproxy/store/libkv"
	"github.com/stugotech/superproxy/store/secret"
)

var logger = golog.NewPackageLogger()

// Configuration keys
const (
	ListenKey = "listen"
)

const (
	acmePathRoot = ".well-known/acme-challenge/"
)

// Proxy accepts incoming requests and proxies them to a configured back end.
type Proxy interface {
	ListenAndServe()
	Shutdown()
}

// proxy is an implementation of Proxy.
type proxy struct {
	configMutex  *sync.RWMutex
	certificates map[string]*tls.Certificate
	hosts        map[string]*store.Host
	store        store.Store
	secretbox    secret.Box
	reverse      *httputil.ReverseProxy
	server       Server
}

// NewProxy creates a new Proxy implementation.
func NewProxy(cfg goconfig.Config) (Proxy, error) {
	st, err := libkv.NewStoreFromConfig(cfg)
	if err != nil {
		return nil, logger.Errore(err)
	}

	secretbox, err := secret.NewBoxFromConfig(cfg)
	if err != nil {
		return nil, logger.Errore(err)
	}

	p := &proxy{
		configMutex:  &sync.RWMutex{},
		certificates: make(map[string]*tls.Certificate),
		hosts:        make(map[string]*store.Host),
		store:        st,
		secretbox:    secretbox,
	}

	p.reverse = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			p.proxyDirector(req)
		},
	}

	mux := http.NewServeMux()
	// handle ACME challenges
	mux.HandleFunc(acmePathRoot, func(res http.ResponseWriter, req *http.Request) {
		p.acmeHandler(res, req)
	})
	// proxy requests
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		p.proxyHandler(res, req)
	})

	listen := cfg.GetStringSlice(ListenKey)
	logger.Info("proxy configuration", golog.Strings("listen", listen))

	srv, err := NewServer(mux, listen, p.getTLSConfig())
	if err != nil {
		return nil, logger.Errore(err)
	}

	p.server = srv

	err = p.watchConfig(nil)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return p, nil
}

// ListenAndServe
func (p *proxy) ListenAndServe() {
	logger.Info("Listening on all configured interfaces", golog.Int("pid", os.Getpid()))
	p.server.ListenAndServe()
}

// Shutdown
func (p *proxy) Shutdown() {
	p.server.Shutdown()
}

// getTLSConfig creates a TLS config.
func (p *proxy) getTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host, err := p.getHost(info.ServerName)
			if err != nil {
				return nil, logger.Errore(err)
			}
			return p.getCertificate(host.CertificateSubject)
		},
	}
}

// acmeHandler handles ACME challenge requests.
func (p *proxy) acmeHandler(res http.ResponseWriter, req *http.Request) {
	logger.Debug("[acmeHandler] received request",
		golog.String("scheme", req.URL.Scheme),
		golog.String("host", req.Host),
		golog.String("url", req.RequestURI),
		golog.String("parsedURI", req.URL.String()),
	)

	host, err := p.getHost(req.Host)
	if err != nil {
		logger.Errore(err)
		http.NotFound(res, req)
		return
	}
	if host.ACMEChallenge.ChallengePath == "" {
		logger.Error("no challenge set for host", golog.String("uri", req.RequestURI))
		http.NotFound(res, req)
		return
	}
	if req.URL.Path != host.ACMEChallenge.ChallengePath {
		logger.Error("unknown challenge", golog.String("uri", req.RequestURI))
		http.NotFound(res, req)
		return
	}
	res.Write([]byte(host.ACMEChallenge.Response))
}

// proxyHandler deals with forwardable requests.
func (p *proxy) proxyHandler(res http.ResponseWriter, req *http.Request) {
	logger.Debug("[proxyHandler] received request",
		golog.String("scheme", req.URL.Scheme),
		golog.String("host", req.Host),
		golog.String("url", req.RequestURI),
		golog.String("parsedURI", req.URL.String()),
	)

	host, err := p.getHost(req.Host)
	if err != nil {
		logger.Errore(err)
		http.NotFound(res, req)
		return
	}
	if req.URL.Scheme == "http" {
		if host.Security == store.SecureOnly {
			logger.Error("unsecure request for secure-only service", golog.String("host", host.Host))
			http.NotFound(res, req)
			return
		}
		if host.Security == store.UpgradeSecurity {
			redirURI := "https://" + req.URL.Host + req.RequestURI
			http.Redirect(res, req, redirURI, http.StatusMovedPermanently)
			return
		}
	} else if req.URL.Scheme == "https" {
		if host.Security == store.UnsecureOnly {
			logger.Error("secure request for unsecure-only service", golog.String("host", host.Host))
			return
		}
	} else {
		logger.Error("unknown scheme", golog.String("scheme", req.URL.Scheme))
		return
	}
	// rewrite and pass to proxy
	req.URL.Scheme = "http"
	req.URL.Host = host.Host
	p.reverse.ServeHTTP(res, req)
}

// proxyDirector feeds the request to a configured back end.
func (p *proxy) proxyDirector(req *http.Request) {
	// proxy director doesn't need to do anything currently because
	// the request is rewritten in proxyHandler()
}

// getHost returns the host with the given domain, or nil if it doesn't exist.
func (p *proxy) getHost(domain string) (*store.Host, error) {
	p.configMutex.RLock()
	host, exists := p.hosts[domain]
	p.configMutex.RUnlock()
	if !exists {
		return nil, logger.Error("unknown host", golog.String("host", domain))
	}
	return host, nil
}

// getCertificate get the certificate for the given host.
func (p *proxy) getCertificate(subject string) (*tls.Certificate, error) {
	p.configMutex.RLock()
	cert, exists := p.certificates[subject]
	p.configMutex.RUnlock()
	if !exists {
		return nil, logger.Error("certificate not found", golog.String("subject", subject))
	}
	return cert, nil
}

// watchConfig watches the configuration and updates the routing data
func (p *proxy) watchConfig(stop <-chan struct{}) error {
	certs, err := p.store.WatchCertificates(stop)
	if err != nil {
		return logger.Errore(err)
	}
	hosts, err := p.store.WatchHosts(stop)
	if err != nil {
		return logger.Errore(err)
	}

	go (func() {
		for certs != nil || hosts != nil {
			select {
			case changes, ok := <-certs: // changes to certificates
				if !ok {
					certs = nil
					continue
				}
				for _, cert := range changes {
					// don't decode in a lock, it's slow
					decoded, err := cert.DecodeCertificate(p.secretbox)
					if err != nil {
						logger.Errore(err)
					}

					p.configMutex.Lock()
					p.certificates[cert.Subject] = decoded
					p.configMutex.Unlock()
				}

			case changes, ok := <-hosts: // changes to hosts
				if !ok {
					hosts = nil
					continue
				}
				p.configMutex.Lock()
				for _, host := range changes {
					p.hosts[host.Host] = host
				}
				p.configMutex.Unlock()

			case <-stop: // stop signalled
				return
			}
		}
	})()

	return nil
}
