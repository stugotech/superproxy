package cmd

import (
	"fmt"
	"os"
	"strconv"

	"io/ioutil"

	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/golog"
	"github.com/stugotech/superproxy/acmelib"
	"github.com/stugotech/superproxy/certmanager"
	"github.com/stugotech/superproxy/store"
	"github.com/stugotech/superproxy/store/secret"
)

var logger = golog.NewPackageLogger()

// Command line flags
const (
	ConfigKey     = "config"
	CPUProfileKey = "cpuprofile"
	PIDFileKey    = "pidfile"
)

// flag defaults
const (
	StoreDefault       = "etcd"
	StorePrefixDefault = "superproxy"
)

// more flag defaults
var (
	StoreNodesDefault = []string{"127.0.0.1:2379"}
)

var cfgFile string
var stopProfile func()

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "superproxy",
	Short: "A simple reverse proxy for use with docker.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		pidFile := viper.GetString(PIDFileKey)
		if pidFile != "" {
			pid := []byte(strconv.FormatInt(int64(os.Getpid()), 10))
			ioutil.WriteFile(pidFile, pid, 0644)
		}
		if viper.GetBool(CPUProfileKey) {
			stopProfile = profile.Start(profile.ProfilePath(".")).Stop
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if stopProfile != nil {
			stopProfile()
		}
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	pf := RootCmd.PersistentFlags()
	pf.StringVar(&cfgFile, ConfigKey, "", "Config file")

	pf.Bool(CPUProfileKey, false, "Produce profiling output")
	pf.String(PIDFileKey, "", "File to output PID to")

	pf.String(secret.SealKey, "", "Key used to encrypt private keys")

	// KV store settings
	pf.String(store.StoreKey, StoreDefault, "Name of the KV store to use [etcd|consul|boltdb|zookeeper]")
	pf.StringSlice(store.StoreNodesKey, StoreNodesDefault, "Comma-seperated list of KV store nodes")
	pf.String(store.StorePrefixKey, StorePrefixDefault, "Base path for values in KV store")

	// ACME flags
	pf.String(certmanager.AcmeDirectoryKey, acmelib.LetsEncryptLiveDirectory, "ACME directory")
	pf.Bool(certmanager.AcceptTOSKey, false, "accept the terms of the ACME service")
	pf.String(certmanager.EmailKey, "", "the contact email address of the registrant")

	viper.BindPFlags(pf)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName(".superproxy") // name of config file (without extension)
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME") // adding home directory as first search path
	viper.AddConfigPath("/etc/superproxy/")
	viper.SetEnvPrefix("superproxy")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logger.Info("Using config file", golog.String("file", viper.ConfigFileUsed()))
	}
}
