package commands

import (
	"github.com/vaguecoder/2fa/pkg/keychain"

	"github.com/spf13/cobra"
)

func NewRootCmd(groupID string, chain keychain.Keychain) *cobra.Command {
	// Forward root commands to show commands
	showCmd := NewShowCmd(groupID, chain)

	rootCmd := cobra.Command{
		Use:   "2fa",
		Short: "Show 2fa code(s)",
		Long: `Show 2fa code(s)
If ran without the key, it lists all the keys and corresponding codes:
  $ 2fa

If ran with the key, it gets the code:
  $ 2fa <key>
		`,
		Args: showCmd.Args, // Keep args in-sync with "show" command
		RunE: showCmd.RunE, // Forward to "show" commands run
	}

	rootCmd.Flags().BoolVarP(&copyToClipboard, "copy", "c", false, "Copy to clipboard (only works with \"2fa <key>\")")

	return &rootCmd
}
