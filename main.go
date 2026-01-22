package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: upki-go-demo <url>")
		os.Exit(1)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				// Standard chain verification has already passed at this point.
				// Add your custom validation logic here.

				fmt.Fprintf(os.Stderr, "Certificate chain has %d verified chain(s)\n", len(verifiedChains))
				for i, chain := range verifiedChains {
					fmt.Fprintf(os.Stderr, "Chain %d:\n", i)
					for j, cert := range chain {
						fmt.Fprintf(os.Stderr, "  [%d] %s\n", j, cert.Subject.CommonName)
					}
				}
				fmt.Fprintln(os.Stderr)

				return nil
			},
		},
	}

	client := &http.Client{Transport: transport}

	resp, err := client.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
}
