#!/bin/bash

set -e

go build -o main .

zip lambda_function.zip main
