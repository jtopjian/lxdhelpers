package lxdhelpers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	lxd "github.com/lxc/lxd/client"
	lxd_config "github.com/lxc/lxd/lxc/config"
	"github.com/lxc/lxd/shared"
)

func ValidateClientCertificates(lxdConfig *lxd_config.Config, generateCertificates bool) error {
	certf := lxdConfig.ConfigPath("client.crt")
	keyf := lxdConfig.ConfigPath("client.key")

	if !shared.PathExists(certf) || !shared.PathExists(keyf) {
		if generateCertificates {
			return shared.FindOrGenCert(certf, keyf, true)
		} else {
			return fmt.Errorf("Certificate or key not found. Either configure this application" +
				"to generate the LXD certificates or use the LXD client to generate them manually.")
		}

	}
	return nil
}

func GetRemoteCertificate(conf *lxd_config.Config, remote string) (lxd.ContainerServer, error) {
	var certificate *x509.Certificate
	var err error

	if _, ok := conf.Remotes[remote]; !ok {
		return nil, fmt.Errorf("Remote %s not found in configuration", remote)
	}

	addr := conf.Remotes[remote]

	tlsConfig, err := shared.GetTLSConfig("", "", "", nil)
	if err != nil {
		return nil, err
	}

	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
		Dial:            shared.RFC3493Dialer,
		Proxy:           shared.ProxyFromEnvironment,
	}

	// Connect to the remote
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Get(addr.Addr)
	if err != nil {
		return nil, err
	}

	// Retrieve the certificate
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("Unable to read remote TLS certificate")
	}

	certificate = resp.TLS.PeerCertificates[0]

	serverCertDir := conf.ConfigPath("servercerts")
	if err := os.MkdirAll(serverCertDir, 0750); err != nil {
		return nil, fmt.Errorf("Could not create server cert dir: %s", err)
	}

	certf := fmt.Sprintf("%s/%s.crt", serverCertDir, remote)
	certOut, err := os.Create(certf)
	if err != nil {
		return nil, err
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	certOut.Close()

	// Set up a new connection, this time with the remote certificate
	return conf.GetContainerServer(remote)
}
