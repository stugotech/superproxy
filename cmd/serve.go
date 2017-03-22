package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/superproxy/proxy"
)

// flag keys
const (
	ListenHTTPKey  = "listenHTTP"
	ListenHTTPSKey = "listenHTTPS"
)

// flag defaults
const (
	ListenHTTPDefault  = ":80"
	ListenHTTPSDefault = ":443"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serves the proxy server on the specified interfaces",
	RunE: func(cmd *cobra.Command, args []string) error {
		v := viper.GetViper()
		v.Set("listen", []string{v.GetString(ListenHTTPKey), v.GetString(ListenHTTPSKey)})

		p, err := proxy.NewProxy(v)
		if err != nil {
			return err
		}
		p.ListenAndServe()
		return nil
	},
}

func init() {
	RootCmd.AddCommand(serveCmd)

	pf := serveCmd.PersistentFlags()
	pf.String(ListenHTTPKey, ListenHTTPDefault, "Interface to listen for incoming requests")
	pf.String(ListenHTTPSKey, ListenHTTPSDefault, "Interface to listen for incoming requests")

	viper.BindPFlags(pf)
}
