package cmd

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/goconfig"
	"github.com/stugotech/superproxy/store/libkv"
)

// hostsRemoveCmd represents the hostsRemove command
var hostsRemoveCmd = &cobra.Command{
	Use:     "remove",
	Short:   "Remove a host",
	Aliases: []string{"rm"},

	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("must specify host name")
		}
		return removeHost(args[0], viper.GetViper())
	},
}

func removeHost(name string, cfg goconfig.Config) error {
	st, err := libkv.NewStoreFromConfig(cfg)
	if err != nil {
		return err
	}

	host, err := st.GetHost(name)
	if err != nil {
		return err
	}
	if host == nil {
		return nil
	}

	err = st.RemoveHost(host.Host)
	if err != nil {
		return err
	}

	if host.CertificateSubject == "" {
		return nil
	}

	cert, err := st.GetCertificate(host.CertificateSubject)
	if err != nil {
		return err
	}
	if cert == nil {
		return nil
	}

	if cert.Subject == host.Host && len(cert.AlternativeNames) == 0 {
		err = st.RemoveCertificate(cert.Subject)
		if err != nil {
			return err
		}
		return nil
	}

	found := -1

	for i, san := range cert.AlternativeNames {
		if san == host.Host {
			found = i
			break
		}
	}

	if found >= 0 {
		cert.AlternativeNames = append(cert.AlternativeNames[:found], cert.AlternativeNames[found:]...)
		err = st.PutCertificate(cert)
		if err != nil {
			return err
		}
	}

	return nil
}

func init() {
	hostsCmd.AddCommand(hostsRemoveCmd)
}
