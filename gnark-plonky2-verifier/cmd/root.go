package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var (
	fBaseDir string
)

var rootCmd = &cobra.Command{
	Use:   "plonky2-gnark-verifier",
	Short: "helper to generate plonky2 proofs in gnark",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&fBaseDir, "dir", "", "base directory for the proof, common_circuit_data, verifier_only_circuit_data")
	rootCmd.MarkPersistentFlagRequired("dir")
}
