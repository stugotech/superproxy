package cmd

import (
	"github.com/spf13/cobra"
)

// sealCmd represents the seal command
var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Commands related to encryption.",
}

func init() {
	RootCmd.AddCommand(sealCmd)
}
