#!/bin/bash

# Location of your suricata conf
CONF_FILE=../conf/suricata.yaml

# Directory of where all the PCAP files are
# These files are downloaded with the wget command
# wget https://download.netresec.com/pcap/FIRST-2015/FIRST-2015_Hands-on_Network_Forensics_PCAP.zip
# and then unzipped in the folder below
SNORT_DIR=/Users/frankhassanabad/projects/first-org-forensics

file_list=()
while IFS= read -d $'\0' -r file ; do
  file_list=("${file_list[@]}" "$file")
done < <(find "${SNORT_DIR}" -name snort.*.* -print0)

# Simple for loop over all the files
# I use `sudo` only so it can have write permissions to /usr/local/var/log/suricata/eve.json
# If you make that file so a non-root user can read/write to it, you do not need sudo
for SNORT_FILE in "${file_list[@]}"
do
  echo $SNORT_FILE
  sudo suricata -v -c $CONF_FILE -r $SNORT_FILE --set unix-command.enabled=false 
done 
