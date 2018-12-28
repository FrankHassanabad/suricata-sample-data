#!/bin/bash

# Install jq
# https://stedolan.github.io/jq/

# Location of your eve file
EVE_FILE=/usr/local/var/log/suricata/eve.json

# Get all unique sorted signature id's as an array
SIGNATURES=(`jq 'select(.alert.signature_id)|.alert.signature_id' ${EVE_FILE} | sort | uniq`)

# Simple for loop over all the signature id's to get a sample alert
file_list=()
for SIGNATURE_ID in "${SIGNATURES[@]}"
do
  sample=`jq "select(.alert.signature_id==$SIGNATURE_ID)" ${EVE_FILE} | jq -s '.[0]'`
  file_list=("${file_list[@]}" "$sample")
done

# Echo out all of the sample alerts
echo "${file_list[@]}" | jq -s '.'
