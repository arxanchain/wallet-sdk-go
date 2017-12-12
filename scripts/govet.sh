#!/bin/bash

set -e

echo "LINT: Running code checks.."
echo "Running go vet"

cd $GOPATH/src/github.com/arxanchain/wallet-sdk-go/

go vet ./api/...
