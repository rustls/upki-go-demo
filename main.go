package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
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

				chain := verifiedChains[0]
				endEntity := chain[0]
				issuer := chain[1]

				// Parse end entity serial (base64 encoded)
				eeSerial := base64.StdEncoding.EncodeToString(endEntity.SerialNumber.Bytes())
				fmt.Fprintf(os.Stderr, "End entity serial: %s\n", eeSerial)

				// Parse issuer SPKI hash (SHA256, base64 encoded)
				issuerSpkiHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
				issuerSpki := base64.StdEncoding.EncodeToString(issuerSpkiHash[:])
				fmt.Fprintf(os.Stderr, "Issuer SPKI hash: %s\n", issuerSpki)

				// Parse SCTs from the certificate
				scts, err := parseSCTs(endEntity)
				if err != nil {
					return fmt.Errorf("failed to parse SCTs: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Found %d SCT(s)\n", len(scts))
				for i, sct := range scts {
					fmt.Fprintf(os.Stderr, "  SCT %d: %s\n", i, sct)
				}
				fmt.Fprintln(os.Stderr)

				// Build command arguments: detail <ee-serial> <issuer-spki> [sct...]
				args := []string{"revocation-check", "detail", eeSerial, issuerSpki}
				args = append(args, scts...)
				cmd := exec.Command("upki", args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
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

// OID for the SCT list extension (1.3.6.1.4.1.11129.2.4.2)
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// parseSCTs extracts SCTs from a certificate's embedded SCT list extension
// Returns strings in format "base64(logID):timestamp"
func parseSCTs(cert *x509.Certificate) ([]string, error) {
	var sctData []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSCTList) {
			// The extension value is an OCTET STRING containing the SCT list
			if _, err := asn1.Unmarshal(ext.Value, &sctData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal SCT extension: %w", err)
			}
			break
		}
	}

	if sctData == nil {
		return nil, nil
	}

	// SCT list format: 2-byte length prefix, then concatenated SCTs
	if len(sctData) < 2 {
		return nil, fmt.Errorf("SCT data too short")
	}

	listLen := int(binary.BigEndian.Uint16(sctData[:2]))
	sctData = sctData[2:]
	if len(sctData) < listLen {
		return nil, fmt.Errorf("SCT list length mismatch")
	}
	sctData = sctData[:listLen]

	var results []string
	for len(sctData) > 0 {
		// Each SCT is prefixed with 2-byte length
		if len(sctData) < 2 {
			break
		}
		sctLen := int(binary.BigEndian.Uint16(sctData[:2]))
		sctData = sctData[2:]
		if len(sctData) < sctLen {
			return nil, fmt.Errorf("SCT length mismatch")
		}

		sct := sctData[:sctLen]
		sctData = sctData[sctLen:]

		// SCT structure: version (1) + log_id (32) + timestamp (8) + ...
		if len(sct) < 1+32+8 {
			continue
		}

		// Log ID is 32 bytes at offset 1
		logID := base64.StdEncoding.EncodeToString(sct[1:33])

		// Timestamp is milliseconds since Unix epoch at offset 33 (1 + 32)
		tsMillis := binary.BigEndian.Uint64(sct[33:41])
		ts := time.UnixMilli(int64(tsMillis))

		results = append(results, fmt.Sprintf("%s:%d", logID, ts.UnixMilli()))
	}

	return results, nil
}
