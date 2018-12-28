#!/bin/bash

# Install jq
# https://stedolan.github.io/jq/

# Location of your eve file
EVE_FILE=/usr/local/var/log/suricata/eve.json

# Get all signature ids
jq 'select(.alert.signature_id)|.alert.signature_id' $EVE_FILE | sort | uniq

# Should list out all the ids like so
# 2001219
# 2001595
# 2001743
# 2002157
# 2002664
# ...
