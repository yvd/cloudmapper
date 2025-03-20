#!/bin/bash

ACCOUNT=$1

if [ -z "$ACCOUNT" ]; then
    ACCOUNT="prod"
fi

python cloudmapper.py collect --account $ACCOUNT
python cloudmapper.py public --account $ACCOUNT > public_out.json
cat public_out.json