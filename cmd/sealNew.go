package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stugotech/superproxy/store/secret"
)

// sealNewCmd represents the sealNew command
var sealNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new seal key.",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := secret.NewKeyString()
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	},
}

func init() {
	sealCmd.AddCommand(sealNewCmd)
}
