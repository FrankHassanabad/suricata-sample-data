#!/bin/bash

# Location of your suricata conf
CONF_FILE=../conf/suricata.yaml

# Directory of where all the PCAP files are
# Example of files to be downloaded with the wget command
# wget -r -np -k https://archive.wrccdc.org/pcaps/2018/
PCAP_DIR=/Users/frankhassanabad/projects/pcaps/wrccdc/archive.wrccdc.org/pcaps/2018

file_list=()
while IFS= read -d $'\0' -r file ; do
  file_list=("${file_list[@]}" "$file")
done < <(find "${PCAP_DIR}" -name *.pcap.gz -print0)

# Simple for loop over all the files
# I use `sudo` only so it can have write permissions to /usr/local/var/log/suricata/eve.json
# If you make that file so a non-root user can read/write to it, you do not need sudo
for i in "${!file_list[@]}"
do
  PCAP_FILE=${file_list[$i]}
  echo "$i/${#file_list[@]} Processing file: $PCAP_FILE"
  gunzip -c "$PCAP_FILE" > /tmp/temp.pcap
  sudo suricata -v -c $CONF_FILE -r "/tmp/temp.pcap" --set unix-command.enabled=false
done 
