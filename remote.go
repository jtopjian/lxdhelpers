package lxdhelpers

import (
	"fmt"

	"github.com/lxc/lxd"
)

func ValidateRemoteConnection(client *lxd.Client, remote string, password string) error {
	// See if the client is already trusted to the server
	if client.AmTrusted() {
		return nil
	}

	// If not, try to authenticate with it
	if err := client.AddMyCertToServer(password); err != nil {
		return fmt.Errorf("Unable to authenticate with remote server: %s", err)
	}

	// Validate client before returning
	if _, err := client.GetServerConfig(); err != nil {
		return err
	}

	return nil
}
