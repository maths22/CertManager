#!/usr/bin/env bash

pkey=$(openssl genpkey -algorithm RSA 2> /dev/null | base64)
name="/${2}/acme-key"

aws ssm get-parameter --region $1 --name "$name" > /dev/null || aws ssm put-parameter --region $1 --name $name --type "SecureString" --value $pkey