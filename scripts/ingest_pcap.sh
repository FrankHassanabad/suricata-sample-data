#!/bin/sh

# Location of your suricata conf
CONF_FILE=../conf/suricata.yaml

# Directory of where all the PCAP files are
PCAP_DIR=/Users/frankhassanabad/projects/pcaps/wrccdc/archive.wrccdc.org/pcaps/2018
PCAP_FILES=(${PCAP_DIR}/*.pcap)

# Uncomment this line if you want to test with 1 file for your configuration first and
# ensure you comment out the above line with a global of all files.  
# PCAP_FILES=${PCAP_DIR}/wrccdc.2018-03-23.010014000000000.pcap

# Simple for loop over all the files
# I use `sudo` only so it can have write permissions to /usr/local/ar/log/suricata/eve.json
# If you make that file so a non-root user can read/write to it, you do not need sudo
for PCAP_FILE in "${PCAP_FILES[@]}"
do
  echo $PCAP_FILE
  sudo suricata -v -c $CONF_FILE -r $PCAP_FILE --set unix-command.enabled=false 
done 
