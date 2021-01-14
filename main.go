package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func main() {

	flag.Parse()

	for _, file := range flag.Args() {
		fmt.Println(strings.Repeat("----------", 6))
		fmt.Println(file)
		fmt.Println(strings.Repeat("----------", 6))
		fmt.Println()

		rest, err := ioutil.ReadFile(file)
		if err != nil {
			log.Println(err)
			continue
		}

		var block *pem.Block

		for {
			block, rest = pem.Decode(rest)

			if block == nil {
				break
			}

			switch block.Type {
			case "PUBLIC KEY":
				_, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					log.Print(err)
				}
			case "CERTIFICATE":
				crt, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					log.Print(err)
					break
				}
				fmt.Printf("Subject:              %s\n", crt.Subject)
				if len(crt.DNSNames) > 0 {
					fmt.Printf("DNS Names:            %s\n", strings.Join(crt.DNSNames, ", "))
				}
				fmt.Printf("Serial Number:        %s\n", crt.SerialNumber)
				fmt.Printf("Issuer:               %s\n", crt.Issuer)
				if crt.Issuer.SerialNumber != "" {
					fmt.Printf("Issuer Serial Number: %s\n", crt.Issuer.SerialNumber)
				}
				fmt.Printf("Is CA:                %t\n", crt.IsCA)
				fmt.Printf("Key Usage:            %s\n", strings.Join(keyUsage(crt.KeyUsage), ", "))
				fmt.Printf("NotBefore:            %s\n", crt.NotBefore.Local())
				fmt.Printf("NotAfter:             %s\n", crt.NotAfter.Local())
				fmt.Printf("Public Key Algorithm: %s\n", crt.PublicKeyAlgorithm)
				fmt.Printf("Public Key Size:      %d\n", keySize(crt.PublicKey))
				fmt.Println()
			case "PRIVATE KEY":
			}
		}
	}
}

func keySize(k interface{}) int {
	var sz = -1
	switch pk := k.(type) {
	case *rsa.PublicKey:
		sz = pk.N.BitLen()
	case *ecdsa.PublicKey:
		sz = pk.X.BitLen()
	case *dsa.PublicKey:
		sz = pk.P.BitLen()
	case ed25519.PublicKey:
		sz = len(pk) * 8
	}
	return sz
}

func keyUsage(u x509.KeyUsage) []string {
	var usages []string

	if u&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if u&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if u&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if u&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if u&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if u&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Cert Sign")
	}
	if u&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if u&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if u&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}
