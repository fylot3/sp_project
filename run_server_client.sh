#!/bin/bash

CWD=$(pwd)
SCRIPT=${CWD}/server_client.py
PRIV_KEY=${CWD}/server_key.priv
PUB_KEY=${CWD}/server_key.pub
PASSWORD_FILE=${CWD}/password.txt
FLAG_FILE=${CWD}/flag.txt

# listen on port 8000, fork when connection received
socat TCP-LISTEN:8000,fork,reuseaddr EXEC:"${SCRIPT} ${PRIV_KEY} ${PUB_KEY} ${PASSWORD_FILE} ${FLAG_FILE}"

