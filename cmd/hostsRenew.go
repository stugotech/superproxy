package cmd

import (
	"math/rand"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/goconfig"
	"github.com/stugotech/superproxy/certmanager"
)

// config keys
const (
	OnceKey = "once"
)

// hostsRenewCmd represents the hostsRenew command
var hostsRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew certificates that are about to expire",
	RunE: func(cmd *cobra.Command, args []string) error {
		return renew(viper.GetViper())
	},
}

func renew(cfg goconfig.Config) error {
	// create a certificate for TLS
	mgr, err := certmanager.NewCertificateManager(cfg)
	if err != nil {
		return err
	}

	once := cfg.GetBool(OnceKey)
	day := time.Duration(24) * time.Hour

	for {
		_, err = mgr.RenewExpiringCertificates(7 * day)
		if err != nil {
			return err
		}

		if once {
			break
		}
		// sleep until tomorrow (plus random offset to be nice to the directory servers)
		time.Sleep(day + time.Duration(rand.Intn(60))*time.Minute)
	}

	return nil
}

func init() {
	hostsCmd.AddCommand(hostsRenewCmd)
	fl := hostsRenewCmd.Flags()
	fl.Bool(OnceKey, false, "run certificate renewal once only rather than continuously")
	viper.BindPFlags(fl)
}
