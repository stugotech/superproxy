package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/superproxy/store/libkv"
)

// hostsListCmd represents the hostsList command
var hostsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all hosts",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := libkv.NewStoreFromConfig(viper.GetViper())
		if err != nil {
			return err
		}

		hosts, err := st.GetHosts()
		if err != nil {
			return err
		}

		for _, host := range hosts {
			fmt.Print(host.Host)
			fmt.Print(": ")
			fmt.Print(host.ProxyTo)
			fmt.Print(" security=")
			fmt.Print(host.Security.String())

			if host.CertificateSubject != "" {
				fmt.Print(" certificate=")
				fmt.Print(host.CertificateSubject)
			}

			fmt.Println("")
		}

		return nil
	},
}

func init() {
	hostsCmd.AddCommand(hostsListCmd)
}
