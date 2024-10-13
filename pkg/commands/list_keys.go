package commands

import (
	"github.com/vaguecoder/2fa/pkg/keychain"

	"github.com/spf13/cobra"
)

func NewListKeysCmd(groupID string, chain keychain.Keychain) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all the 2FA keys",
		Long:    "List all the 2FA keys",
		GroupID: groupID,
		Example: "2fa list <key> <value>",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			chain.List()
		},
	}
}
