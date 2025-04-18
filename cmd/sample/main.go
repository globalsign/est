package main

import (
	"context"
	"fmt"
)

func main() {
	// ------ Setup ------

	// To make the sample work, provide
	// 		- EST server host (cf. est client instantiation)
	// 		- EST http basic creds if necessary (cf. est client instantiation)

	// instantiate an insecure EST client to retrieve the CA certs
	insecureEST := newEstClient(newConfig(nil))

	if insecureEST == nil {
		panic("Failed to create EST client")
	}

	fmt.Println("********************** CACerts Operation *****************************")
	cacerts, err := insecureEST.CACerts(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Printf("CaCerts returns %v certificates.\n", len(cacerts))
	fmt.Println("1st cert - subject : ", cacerts[0].Subject.CommonName)
	fmt.Println("2nd cert - subject : ", cacerts[1].Subject.CommonName)

	// est client boostrapped with the CA cert
	root := cacerts[len(cacerts)-1]
	estc := newEstClient(newConfig(root))

	fmt.Println()
	fmt.Println("********************** Enroll Operation *****************************")

	csr, err := newCSR(subjectCN, estc.PrivateKey)
	if err != nil {
		panic(err)
	}

	c, err := estc.Enroll(context.Background(), csr)

	if err != nil {
		panic(err)
	}

	fmt.Println("enrolled certificate CN: ", c.Subject.CommonName)
	fmt.Println("enrolled certificate issuer: ", c.Issuer)
}
