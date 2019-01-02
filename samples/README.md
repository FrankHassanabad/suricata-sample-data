Each sample folder contains:

A sampling of 1 unique alert from its `eve.json` created through

```sh
scripts/get_alert_samples.sh > alerts-only.json
```

A `ids-list.txt` which is a unique list of ids created through

```sh
jq '.[]|.alert.signature_id' alerts-only.json > ids-list.txt
```

A list of signatures that map 1-1 with the ids-list created through

```sh
jq '.[].alert.signature' alerts-only.json > signature-list.txt
```

A list of id's, signature names, and hyperlinks from the rules references section

```sh
scripts/get_references.sh > references.md
```

The mission of the Collegiate Cyber Defense Competition (CCDC) system

http://www.wrccdc.org/

Hands-on Network Forensics - Training PCAP dataset from FIRST 2015

https://www.netresec.com/?page=PcapFiles

https://www.first.org/conference/2015/program#phands-on-network-forensics

honeypot-2018 - That was a small honey pot I stood up on digital ocean using
Modern HoneyPot Network  
https://threatstream.github.io/mhn/
