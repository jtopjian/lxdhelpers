package lxdhelpers

import (
	"fmt"

	lxd "github.com/lxc/lxd/client"
	"github.com/lxc/lxd/shared/api"
)

func ValidateRemoteConnection(client lxd.ContainerServer, remote string, password string) error {
	srv, _, err := client.GetServer()
	// See if the client is already trusted to the server
	if srv.Auth == "trusted" {
		return nil
	}

	req := api.CertificatesPost{
		Password: password,
	}
	req.Type = "client"

	err = client.CreateCertificate(req)
	if err != nil {
		return fmt.Errorf("Unable to authenticate with remote server: %s", err)
	}

	// Validate client before returning
	srv, _, err = client.GetServer()
	if srv.Auth == "trusted" {
		return nil
	}

	return nil
}
