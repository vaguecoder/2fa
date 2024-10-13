package commands

import (
	"fmt"

	"github.com/vaguecoder/2fa/pkg/keychain"

	"github.com/spf13/cobra"
)

var (
	sizeOfGeneratedCode int
	isHOTP              bool
)

func NewAddCmd(groupID string, chain keychain.Keychain) *cobra.Command {
	addCmd := cobra.Command{
		Use:     "add",
		Short:   "Add a 2FA key",
		Long:    "Add a 2FA key",
		GroupID: groupID,
		Example: "2fa add <key> <value>",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyName := args[0]
			secret := args[1]

			if err := validateAddCmdFlags(keyName, secret, sizeOfGeneratedCode); err != nil {
				return err
			}

			if err := chain.Add(keyName, secret, isHOTP, sizeOfGeneratedCode); err != nil {
				return fmt.Errorf("failed to add key %q: %v", keyName, err)
			}

			return nil
		},
	}

	addCmd.Flags().BoolVar(&isHOTP, "hotp", false, "Is an hash-based OTP")
	addCmd.Flags().IntVarP(&sizeOfGeneratedCode, "size", "s", 6, "Size of generated code (6-8)")

	return &addCmd
}

func validateAddCmdFlags(keyName, secret string, sizeOfGeneratedCode int) error {
	if keyName == "" {
		return fmt.Errorf("missing key (--key)")
	}

	if secret == "" {
		return fmt.Errorf("missing secret (--secret)")
	}

	if sizeOfGeneratedCode < 6 || sizeOfGeneratedCode > 8 {
		return fmt.Errorf("invalid size of generated code: %d, possible values 6-8", sizeOfGeneratedCode)
	}

	return nil
}
