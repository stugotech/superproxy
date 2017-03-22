package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"

	"time"

	"github.com/stugotech/golog"
	"github.com/stugotech/superproxy/syncex"
)

const (
	// GracefulShutdownTimeoutS is the time allowed (in seconds) for graceful shutdown to finish
	// before forced termination is started.
	GracefulShutdownTimeoutS = 5
)

// Server represents a multi-interface server.
type Server interface {
	ListenAndServe()
	Shutdown()
}

// server is an implementation of Server.
type server struct {
	listeners []*listener
	handler   http.Handler
	workers   syncex.WorkerPool
}

// listener represents an interface for a Server.
type listener struct {
	addr   string
	tls    bool
	server *http.Server
}

// NewServer creates a new server with the given handler, which will listen on each of the given
// interfaces.
func NewServer(handler http.Handler, interfaces []string, tlsConfig *tls.Config) (Server, error) {
	listeners, err := createListeners(handler, interfaces, tlsConfig)
	if err != nil {
		return nil, err
	}
	return &server{
		handler:   handler,
		listeners: listeners,
		workers:   syncex.NewWorkerPool(),
	}, nil
}

// ListenAndServe
func (s *server) ListenAndServe() {
	for _, l := range s.listeners {
		s.workers.BeginWork(l.listen, l.shutdown)
	}
	s.workers.WaitWorkers()
}

// Shutdown
func (s *server) Shutdown() {
	s.workers.Close()
}

// listen starts the server listening.
func (l *listener) listen() {
	var err error
	if l.tls {
		err = l.server.ListenAndServeTLS("", "")
	} else {
		err = l.server.ListenAndServe()
	}

	logger.Errore(err)
}

// shutdown stops the server listening.
func (l *listener) shutdown() {
	to := time.Duration(GracefulShutdownTimeoutS) * time.Second
	toContext, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()

	err := l.server.Shutdown(toContext)
	if err != nil {
		logger.Errore(err)
		if err = l.server.Close(); err != nil {
			logger.Errore(err)
		}
	}
}

// createListeners creates a listener for each interface.
func createListeners(handler http.Handler, interfaces []string, tlsConfig *tls.Config) ([]*listener, error) {
	var listeners = make([]*listener, len(interfaces))

	for i, addr := range interfaces {
		l, err := createListener(handler, addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		listeners[i] = l
	}

	return listeners, nil
}

func createListener(handler http.Handler, addr string, tlsConfig *tls.Config) (*listener, error) {
	logger.Debug("creating listener", golog.String("address", addr))

	addrURL, err := url.Parse(addr)
	if err != nil {
		return nil, logger.Errorex("can't parse interface URL", err, golog.String("address", addr))
	}
	if addrURL.Path != "" {
		return nil, logger.Error("not an interface - specify http or https scheme and authority only",
			golog.String("address", addr),
		)
	}

	l := &listener{
		addr: addrURL.Host,
		server: &http.Server{
			Addr:    addrURL.Host,
			Handler: handler,
		},
	}

	if addrURL.Scheme == "https" {
		if tlsConfig == nil {
			return nil, logger.Error("no TLS config provided")
		}
		l.tls = true
		l.server.TLSConfig = tlsConfig
	} else if addrURL.Scheme != "http" {
		return nil, logger.Error("not an interface - specify http or https scheme and authority only",
			golog.String("address", addr),
		)
	}

	return l, nil
}
