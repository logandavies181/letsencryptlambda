package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/registration"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// Implement the acme.User interface. Copied from https://go-acme.github.io/lego/usage/library/
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {
	lambda.Start(LambdaHandler)
}

func uploadToS3(payload []byte, key string) {
	session, err := session.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	s3Session := s3.New(session)

	body := bytes.NewReader(payload)

	bucket := os.Getenv("BUCKET_NAME")
	req, _ := s3Session.PutObjectRequest(&s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   body,
	})

	err = req.Send()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Uploaded %v successfully", key)
}

// LambdaHandler gets a cert using route53 dns challenge and upload to s3
func LambdaHandler() {

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	email := os.Getenv("EMAIL")
	myUser := MyUser{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// CADirURL is which CA to try the ACME protocol to
	// Values from: https://github.com/go-acme/lego/blob/master/lego/client_config.go
	// Let's Encrypt Staging: "https://acme-staging-v02.api.letsencrypt.org/directory"
	// Let's Encrypt Prod: "https://acme-staging-v02.api.letsencrypt.org/directory"
	caDirURL := os.Getenv("CA_DIR_URL")
	if caDirURL == "" {
		caDirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// Set up route53 dns-01 challenge provider
	route53Config := route53.NewDefaultConfig()
	route53Config.PropagationTimeout = time.Second * 300
	route53Provider, err := route53.NewDNSProviderConfig(route53Config)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Challenge.SetDNS01Provider(route53Provider)
	if err != nil {
		log.Fatal(err)
	}

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	domain := os.Getenv("DOMAIN")
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	uploadToS3(certificates.Certificate, fmt.Sprintf("%v.crt", domain))
	uploadToS3(certificates.PrivateKey, fmt.Sprintf("%v.key", domain))

	// TODO maybe log the modulus or something to identify the new cert
	log.Print("Success")
}
