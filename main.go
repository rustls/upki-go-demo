package main

/*
#cgo CFLAGS: -I${SRCDIR}/../upki/upki-ffi
#cgo LDFLAGS: -L${SRCDIR}/../upki/target/release -lupki
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation -lresolv
#cgo linux LDFLAGS: -Wl,-rpath,${SRCDIR}/../upki/target/release -lm -ldl -lpthread

#include "upki.h"
*/
import "C"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: upki-go-demo <url>")
		os.Exit(1)
	}

	// Initialize upki config
	var config *C.upki_config
	result := C.upki_config_new(&config)
	if result != C.UPKI_OK {
		fmt.Fprintf(os.Stderr, "failed to create upki config: %d\n", result)
		os.Exit(1)
	}
	defer C.upki_config_free(config)

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

				chain := verifiedChains[0]
				cCerts := make([]C.upki_certificate_der, len(chain))
				var pinner runtime.Pinner
				for i, cert := range chain {
					pinner.Pin(&cert.Raw[0])
					cCerts[i].data = (*C.uint8_t)(unsafe.Pointer(&cert.Raw[0]))
					cCerts[i].len = C.uintptr_t(len(cert.Raw))
				}

				result := C.upki_check_revocation(
					config,
					&cCerts[0],
					C.uintptr_t(len(cCerts)),
				)
				pinner.Unpin()

				switch result {
				case C.UPKI_OK:
					fmt.Fprintln(os.Stderr, "Revocation check: OK")
					return nil
				case C.UPKI_REVOCATION_NOT_COVERED:
					fmt.Fprintln(os.Stderr, "Revocation check: not covered")
					return nil
				case C.UPKI_REVOCATION_REVOKED:
					return fmt.Errorf("Revocation check: revoked")
				case C.UPKI_REVOCATION_NOT_REVOKED:
					fmt.Fprintln(os.Stderr, "Revocation check: not revoked")
					return nil
				default:
					return fmt.Errorf("upki revocation check failed with error: %d", result)
				}
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
