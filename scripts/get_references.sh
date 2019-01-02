#!/bin/bash

# Install jq
# https://stedolan.github.io/jq/

# Download the suricata rules ref db from my other project of:
# https://github.com/FrankHassanabad/suricata-sid-database
# To use locally for jq queries
curl https://raw.githubusercontent.com/FrankHassanabad/suricata-sid-database/master/data/suricata-rules-ref.json > suricata-rules-ref.json 

# alert samples to get references from
# uncomment which eve file to get the references from
# EVE_FILE=../samples/first-org-conf-2015/alerts-only.json
# EVE_FILE=../samples/wrccdc-2017/alerts-only.json
# EVE_FILE=../samples/honeypot-2018/alerts-only.json
EVE_FILE=../samples/wrccdc-2018/alerts-only.json

# Get all unique sorted signature id's as an array
SIGNATURE_IDS=(`jq '.[]|.alert.signature_id' ${EVE_FILE}`)

# Simple for loop over all the signature id's to get 
file_list=()
for i in "${!SIGNATURE_IDS[@]}"
do
  SIGNATURE_ID=${SIGNATURE_IDS[$i]}
  SIGNATURE=`jq ".[]|select(.alert.signature_id==$SIGNATURE_ID)|.alert.signature" ${EVE_FILE}`
  ref=`jq .\"$SIGNATURE_ID\" suricata-rules-ref.json`
  file_list=("${file_list[@]}" "sid: $SIGNATURE_ID signature: $SIGNATURE")
  file_list=("${file_list[@]}" "$ref")
  file_list=("${file_list[@]}" "")
done

# Echo out all of the alerts with references if any were found
for file in "${file_list[@]}"
do
  echo $file
done
