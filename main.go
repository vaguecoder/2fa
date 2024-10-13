// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/vaguecoder/2fa/pkg/commands"
	"github.com/vaguecoder/2fa/pkg/keychain"

	"github.com/spf13/cobra"
)

func main() {
	userHome, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("failed to find user's home directory: %v", err)
	}
	filename := filepath.Join(userHome, ".2fa")

	chain, err := newKeychain(filename)
	if err != nil {
		log.Fatalf("failed to read keychain file: %v", err)
	}

	err = build2FACmd(chain).Execute()
	if err != nil {
		// Cobra prints the errors in output anyway
		os.Exit(1)
	}
}

func newKeychain(keychainFilename string) (keychain.Keychain, error) {
	keychainFile, err := os.OpenFile(keychainFilename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %q: %v", keychainFilename, err)
	}

	chain, err := keychain.ReadKeychain(keychainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read keychain: %v", err)
	}

	return chain, nil
}

func build2FACmd(chain keychain.Keychain) *cobra.Command {
	root2faCmdGroups := cobra.Group{
		ID:    "2fa",
		Title: "Root 2fa commands",
	}

	rootCmd := commands.NewRootCmd(root2faCmdGroups.ID, chain)
	addCmd := commands.NewAddCmd(root2faCmdGroups.ID, chain)
	listKeysCmd := commands.NewListKeysCmd(root2faCmdGroups.ID, chain)
	showCmd := commands.NewShowCmd(root2faCmdGroups.ID, chain)

	rootCmd.AddGroup(&root2faCmdGroups)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listKeysCmd)
	rootCmd.AddCommand(showCmd)

	return rootCmd
}
