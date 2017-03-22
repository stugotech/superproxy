package cmd

import (
	"errors"

	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/goconfig"
	"github.com/stugotech/superproxy/certmanager"
	"github.com/stugotech/superproxy/store"
	"github.com/stugotech/superproxy/store/libkv"
)

// config keys
const (
	SecurityModeKey = "security"
)

// hostsAddCmd represents the hostsAdd command
var hostsAddCmd = &cobra.Command{
	Use:   "add [host] [backend]",
	Short: "add a host",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return errors.New("expected host and backend values")
		}
		return addCert(viper.GetViper(), args[0], args[1])
	},
}

func addCert(cfg goconfig.Config, host string, backend string) error {
	modeStr := cfg.GetString(SecurityModeKey)
	mode, err := store.ParseSecurityMode(modeStr)
	if err != nil {
		return err
	}

	hostData := &store.Host{
		Host:     host,
		ProxyTo:  backend,
		Security: mode,
	}

	if mode != store.UnsecureOnly {
		// create a certificate for TLS
		mgr, err := certmanager.NewCertificateManager(cfg)
		if err != nil {
			return err
		}

		cert, err := mgr.EnsureCertificate(host)
		if err != nil {
			return err
		}

		hostData.CertificateSubject = cert.Subject
	}

	st, err := libkv.NewStoreFromConfig(cfg)
	if err != nil {
		return err
	}

	// save host data
	err = st.PutHost(hostData)
	if err != nil {
		return err
	}

	return nil
}

func init() {
	hostsCmd.AddCommand(hostsAddCmd)
	fl := hostsAddCmd.Flags()

	fl.String(SecurityModeKey, store.UpgradeSecurityStr,
		fmt.Sprintf("The security mode [%s|%s|%s|%s]",
			store.UpgradeSecurityStr, store.SecureOnlyStr,
			store.UnsecureOnlyStr, store.SecureAndUnsecureStr,
		),
	)

	viper.BindPFlags(fl)
}
