#!/bin/sh

# Location of your suricata conf
export CONF_FILE=/usr/local/etc/suricata/suricata.yaml

# Directory of where all the PCAP files are
export PCAP_DIR=/Users/frankhassanabad/projects/pcaps/wrccdc/archive.wrccdc.org/pcaps/2018/
export PCAP_FILES=(${PCAP_DIR}/*.pcap)

# Uncomment this line if you want to test with 1 file for your configuration first and 
# export PCAP_FILE=${PCAP_DIR}/wrccdc.2018-03-23.010014000000000.pcap

for PCAP_FILE in "${PCAP_FILES[@]}"
do
  echo $PCAP_FILE
  sudo suricata -v -c $CONF_FILE -r $PCAP_FILE --set unix-command.enabled=false 
done 
