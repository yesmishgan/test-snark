#!/bin/bash

## Note this script is meant for dev purposes only. Certificate management and authenticity 
## verification in the gRPC client is necessarly for a secure deployment.
openssl req \
  -subj "/C=US/ST=Texas/L=Texas/O=ConsenSys/OU=test-snark/CN=example.com" \
  -newkey rsa:2048 -nodes \
  -keyout gnarkd.key \
  -out gnarkd.csr
openssl x509 -req -sha256 -days 365 -in test-snark.csr -signkey test-snark.key -out test-snark.crt