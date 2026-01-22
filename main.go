package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: upki-go-demo <url>")
		os.Exit(1)
	}

	// Load system roots explicitly to force pure-Go verifier
	// (when RootCAs is non-nil, Go uses its own chain builder instead of platform verifier)
	roots, err := x509.SystemCertPool()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load system roots:", err)
		os.Exit(1)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				os.Stderr.Sync()

				fmt.Fprintf(os.Stderr, "Certificate chain has %d verified chain(s)\n", len(verifiedChains))
				for i, chain := range verifiedChains {
					fmt.Fprintf(os.Stderr, "Chain %d:\n", i)
					for j, cert := range chain {
						fmt.Fprintf(os.Stderr, "  [%d] %s\n", j, cert.Subject.CommonName)
					}
				}
				fmt.Fprintln(os.Stderr)

				cmd := exec.Command("upki", "revocation-check", "high")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				stdin, err := cmd.StdinPipe()
				if err != nil {
					return fmt.Errorf("failed to create stdin pipe: %w", err)
				} else if err := cmd.Start(); err != nil {
					return fmt.Errorf("failed to start upki: %w", err)
				}

				chain := verifiedChains[0]
				for i := 0; i < 2 && i < len(chain); i++ {
					pem.Encode(stdin, &pem.Block{
						Type:  "CERTIFICATE",
						Bytes: chain[i].Raw,
					})
				}
				stdin.Close()

				err = cmd.Wait()
				if err != nil {
					if exitErr, ok := err.(*exec.ExitError); ok {
						return fmt.Errorf("upki revocation-check failed with exit code %d", exitErr.ExitCode())
					}
					return fmt.Errorf("upki revocation-check failed: %w", err)
				}

				return nil
			},
		},
	}

	client := &http.Client{Transport: transport}

	os.Stderr.Sync()
	resp, err := client.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
}
