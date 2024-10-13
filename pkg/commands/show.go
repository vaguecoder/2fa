package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vaguecoder/2fa/pkg/keychain"
)

var copyToClipboard bool

func NewShowCmd(groupID string, chain keychain.Keychain) *cobra.Command {
	showCmd := cobra.Command{
		Use:   "show",
		Short: "Show 2fa code(s)",
		Long: `Show 2fa code(s)
If ran without the key, it lists all the keys and corresponding codes:
  $ 2fa show

If ran with the key, it gets the code:
  $ 2fa show <key>
		`,
		GroupID: groupID,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				key := args[0]
				if err := chain.Show(key, copyToClipboard); err != nil {
					return fmt.Errorf("failed to show code for key %q in keychain: %v", key, err)
				}

				return nil
			}

			if err := chain.ShowAll(); err != nil {
				return fmt.Errorf("failed to show codes for all keys in keychain: %v", err)
			}

			return nil
		},
	}

	showCmd.Flags().BoolVarP(&copyToClipboard, "copy", "c", false, "Copy to clipboard (only works with \"2fa show <key>\")")

	return &showCmd
}
