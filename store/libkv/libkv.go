package libkv

import (
	"path/filepath"

	"encoding/json"

	"github.com/docker/libkv"
	libkvst "github.com/docker/libkv/store"
	"github.com/docker/libkv/store/boltdb"
	"github.com/docker/libkv/store/consul"
	"github.com/docker/libkv/store/etcd"
	"github.com/docker/libkv/store/zookeeper"
	"github.com/stugotech/goconfig"
	"github.com/stugotech/golog"
	"github.com/stugotech/superproxy/store"
)

var logger = golog.NewPackageLogger()

// Configuration keys
const (
	StoreKey       = "store"
	StoreNodesKey  = "store-nodes"
	StorePrefixKey = "store-prefix"
)

// libkvStore implements the Store interface using Docker's libkv package
type libkvStore struct {
	store  libkvst.Store
	prefix string
}

const (
	acmeAccountsPath = "acme/accounts"
	certificatesPath = "certificates"
	hostsPath        = "hosts"
)

// NewStoreFromConfig creates a new store based on the provided config.
func NewStoreFromConfig(conf goconfig.Config) (store.Store, error) {
	store := conf.GetString(StoreKey)
	storeNodes := conf.GetStringSlice(StoreNodesKey)
	storePrefix := conf.GetString(StorePrefixKey)

	if store == "" || len(storeNodes) == 0 || storePrefix == "" {
		return nil, logger.Error("must set store name, nodes and prefix")
	}

	return NewStore(
		store,
		storeNodes,
		storePrefix,
	)
}

// NewStore creates a new store with the given parameters.
func NewStore(storeName string, nodes []string, prefix string) (store.Store, error) {
	etcd.Register()
	consul.Register()
	boltdb.Register()
	zookeeper.Register()

	storeConfig := &libkvst.Config{}
	s, err := libkv.NewStore(libkvst.Backend(storeName), nodes, storeConfig)

	if err != nil {
		return nil, logger.Errore(err)
	}

	return &libkvStore{
		store:  s,
		prefix: prefix,
	}, nil
}

// GetACMEAccount
func (s *libkvStore) GetACMEAccount(email string) (*store.ACMEAccount, error) {
	var acc store.ACMEAccount
	found, err := s.get(&acc, acmeAccountsPath, email)
	if found {
		return &acc, err
	}
	return nil, err
}

// GetCertificate
func (s *libkvStore) GetCertificate(subject string) (*store.Certificate, error) {
	var cert store.Certificate
	found, err := s.get(&cert, certificatesPath, subject)
	if found {
		return &cert, err
	}
	return nil, err
}

// GetHost
func (s *libkvStore) GetHost(hostName string) (*store.Host, error) {
	var host store.Host
	found, err := s.get(&host, hostsPath, hostName)
	if found {
		return &host, err
	}
	return nil, err
}

// PutACMEAccount
func (s *libkvStore) PutACMEAccount(account *store.ACMEAccount) error {
	if account.Email == "" {
		return logger.Error("must specify email for account")
	}
	if account.URI == "" {
		return logger.Error("must specify URI for account")
	}
	if len(account.Key) == 0 {
		return logger.Error("must specify key for account")
	}
	return s.put(account, acmeAccountsPath, account.Email)
}

// PutCertificate
func (s *libkvStore) PutCertificate(cert *store.Certificate) error {
	if cert.Subject == "" {
		return logger.Error("must specify subject for certificate")
	}
	if len(cert.PrivateKey) == 0 {
		return logger.Error("must specify private key for certificate")
	}
	return s.put(cert, certificatesPath, cert.Subject)
}

// PutHost
func (s *libkvStore) PutHost(host *store.Host) error {
	if host.Host == "" {
		return logger.Error("must specify host name for host")
	}
	if host.Security != store.UnsecureOnly && host.CertificateSubject == "" {
		return logger.Error("must specify certificate for host for HTTPS support")
	}
	return s.put(host, hostsPath, host.Host)
}

// GetCertificates
func (s *libkvStore) GetCertificates() ([]*store.Certificate, error) {
	key := s.path(certificatesPath)

	kvs, err := s.store.List(key)
	if err != nil {
		return nil, logger.Errorex("error getting values from store", err, golog.String("key", key))
	}

	values := make([]*store.Certificate, len(kvs))

	for i, kv := range kvs {
		value := &store.Certificate{}

		err = json.Unmarshal(kv.Value, value)
		if err != nil {
			return nil, logger.Errorex("error decoding value from store", err, golog.String("key", key))
		}
		values[i] = value
	}

	return values, nil
}

// GetHosts
func (s *libkvStore) GetHosts() ([]*store.Host, error) {
	key := s.path(hostsPath)

	kvs, err := s.store.List(key)
	if err != nil {
		return nil, logger.Errorex("error getting values from store", err, golog.String("key", key))
	}

	values := make([]*store.Host, len(kvs))

	for i, kv := range kvs {
		value := &store.Host{}

		err = json.Unmarshal(kv.Value, value)
		if err != nil {
			return nil, logger.Errorex("error decoding value from store", err, golog.String("key", key))
		}
		values[i] = value
	}

	return values, nil
}

// WatchCertificates
func (s *libkvStore) WatchCertificates(stop <-chan struct{}) (<-chan []*store.Certificate, error) {
	changes, err := s.watchTree(certificatesPath, stop)
	if err != nil {
		return nil, logger.Errore(err)
	}

	out := make(chan []*store.Certificate)

	go (func() {
		defer close(out)

		for {
			select {
			case <-stop:
				return
			case batch, ok := <-changes:
				if !ok {
					logger.Debug("certificate watcher closed")
					return
				}
				logger.Debug("detected changes to certificates", golog.Int("n", len(batch)))
				values := make([]*store.Certificate, len(batch))

				for i, kv := range batch {
					value := &store.Certificate{}

					err = json.Unmarshal(kv.Value, value)
					if err != nil {
						logger.Errorex("error decoding value from store", err)
					}

					values[i] = value
				}

				out <- values
			}
		}
	})()

	return out, nil
}

// WatchHosts
func (s *libkvStore) WatchHosts(stop <-chan struct{}) (<-chan []*store.Host, error) {
	changes, err := s.watchTree(hostsPath, stop)
	if err != nil {
		return nil, logger.Errore(err)
	}

	out := make(chan []*store.Host)

	go (func() {
		defer close(out)

		for {
			select {
			case <-stop:
				return
			case batch, ok := <-changes:
				if !ok {
					logger.Debug("host watcher closed")
					return
				}
				values := make([]*store.Host, len(batch))

				for i, kv := range batch {
					value := &store.Host{}

					err = json.Unmarshal(kv.Value, value)
					if err != nil {
						logger.Errorex("error decoding value from store", err)
					}

					values[i] = value
				}

				out <- values
			}
		}
	})()

	return out, nil
}

// get gets a value from the store.
func (s *libkvStore) get(value interface{}, path ...string) (bool, error) {
	key := s.path(path...)

	kv, err := s.store.Get(key)
	if err == libkvst.ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, logger.Errorex("error getting value from store", err, golog.String("key", key))
	}

	err = json.Unmarshal(kv.Value, value)
	if err != nil {
		return false, logger.Errorex("error decoding value from store", err, golog.String("key", key))
	}

	return true, nil
}

// put puts a value into the store.
func (s *libkvStore) put(value interface{}, path ...string) error {
	key := s.path(path...)

	buf, err := json.Marshal(value)
	if err != nil {
		return logger.Errorex("error encoding value while writing to store", err, golog.String("key", key))
	}

	err = s.store.Put(key, buf, nil)
	if err != nil {
		return logger.Errorex("error writing value to store", err)
	}

	return nil
}

// watchTree
func (s *libkvStore) watchTree(key string, stop <-chan struct{}) (<-chan []*libkvst.KVPair, error) {
	key = s.path(key)
	logger.Debug("watching store path", golog.String("path", key))

	exists, err := s.store.Exists(key)
	if err != nil {
		return nil, logger.Errorex("error watching key in store", err, golog.String("key", key))
	}
	if !exists {
		logger.Debug("key doesn't exist", golog.String("key", key))
		err = s.store.Put(key, nil, &libkvst.WriteOptions{IsDir: true})
		if err != nil {
			return nil, logger.Errorex("error watching key in store", err, golog.String("key", key))
		}
	}

	changes, err := s.store.WatchTree(key, stop)
	if err != nil {
		return nil, logger.Errorex("error watching key in store", err, golog.String("key", key))
	}

	return changes, nil
}

// path constructs a path from the given components.
func (s *libkvStore) path(components ...string) string {
	components = append([]string{s.prefix}, components...)
	return filepath.Join(components...)
}
