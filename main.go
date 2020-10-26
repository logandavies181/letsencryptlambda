package main

import (
	"github.com/aws/aws-lambda-go/lambda"

	"letsencryptlambda/acme"
)

func main() {
	lambda.Start(acme.GetCert)
}
