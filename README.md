# suricata-sample-data

This is a project and repository of different outputs of Suricata run against different
[pcap](https://en.wikipedia.org/wiki/Pcap) data sets. You can download the Suricata data
sets from the releases page of this repository.

[eve.json files](https://github.com/FrankHassanabad/suricata-sample-data/releases/download/v3.0.0/release.zip)

# Select samples of alerts from the zip

Samples README and starting folder of the files generated from the eve files  
[samples](samples)

## The mission of the Collegiate Cyber Defense Competition (CCDC) system 2018

[samples/wrccdc-2018](samples/wrccdc-2018) are generated from http://www.wrccdc.org/
mirrored [here](https://archive.wrccdc.org/pcaps/2018/)

A sampling of 1 of each alert from its eve.json  
[samples/wrccdc-2018/alerts-only.json](samples/wrccdc-2018/alerts-only.json)

A list of id's, signature names, and hyperlinks from the rules references section
[samples/wrccdc-2018/references.md](samples/wrccdc-2018/references.md)

A list of id's, sampling of 1 of each alert from its eve.json  
[samples/wrccdc-2018/alerts-only.json](samples/wrccdc-2018/alerts-only.json)

A unique list of sids (Suricata Id's)  
[samples/wrccdc-2018/ids-list.txt](samples/wrccdc-2018/ids-list.txt)

A list of signatures that map 1-1 with the ids-list  
[samples/wrccdc-2018/signature-list.txt](samples/wrccdc-2018/signature-list.txt)

![topology](img/wrccdc2018-topology.png?raw=true)

## The mission of the Collegiate Cyber Defense Competition (CCDC) system 2017

[samples/wrccdc-2017](samples/wrccdc-2017) are generated from http://www.wrccdc.org/
mirrored [here](https://archive.wrccdc.org/pcaps/2017/)

A sampling of 1 of each alert from its eve.json  
[samples/wrccdc-2017/alerts-only.json](samples/wrccdc-2017/alerts-only.json)

A list of id's, signature names, and hyperlinks from the rules references section
[samples/wrccdc-2018/references.md](samples/wrccdc-2018/references.md)

A unique list of sids (Suricata Id's)  
[samples/wrccdc-2017/ids-list.txt](samples/wrccdc-2017/ids-list.txt)

A list of signatures that map 1-1 with the ids-list  
[samples/wrccdc-2017/signature-list.txt](samples/wrccdc-2017/signature-list.txt)

![topology](img/wrccdc2017-topology.png?raw=true)

## Hands-on Network Forensics - Training PCAP dataset from FIRST 2015

[samples/first-org-conf-2015](samples/first-org-conf-2015) are generated from
the pcaps [mirrored here](https://www.netresec.com/?page=PcapFiles) from
the [first.org conference](https://www.first.org/conference/2015/program#phands-on-network-forensics)

A sampling of 1 of each alert from its eve.json  
[samples/first-org-conf-2015/alerts-only.json](samples/first-org-conf-2015/alerts-only.json)

A list of id's, signature names, and hyperlinks from the rules references section
[samples/wrccdc-2018/references.md](samples/wrccdc-2018/references.md)

A unique list of sids (Suricata Id's)  
[samples/first-org-conf-2015/ids-list.txt](samples/first-org-conf-2015/ids-list.txt)

A list of signatures that map 1-1 with the ids-list  
[samples/first-org-conf-2015/signature-list.txt](samples/first-org-conf-2015/signature-list.txt)

![topology](img/pawned-se.png?raw=true)

Optionally you can read below on how to (re)create your own data sets from your own
[pcap](https://en.wikipedia.org/wiki/Pcap) files and Suricata rules.

# Background

[Suricata](https://suricata-ids.org/) is an engine that is capable of real
time intrusion detection [IDS](https://en.wikipedia.org/wiki/Intrusion_detection_system),
inline intrusion prevention [IPS](https://en.wikipedia.org/wiki/Intrusion_detection_system),
network security monitoring (NSM) and offline pcap processing.

This repository contains sample `eve.json` log files created by Suricata from
existing [pcap](https://en.wikipedia.org/wiki/Pcap) files as well as instructions
on how to create them yourself. This is useful if you want to see what _alerts only_
data sets look like or play with the rules yourself and re-create your
own [eve](https://suricata.readthedocs.io/en/suricata-4.1.2/output/eve/eve-json-output.html)
files for learning purposes to write your own `eve.json` real time simulator.

The pcaps I found interesting for rich data was the
[The Western Regional Cyber Defense 2018 (wrccdc)](http://www.wrccdc.org/). wrccdc has a rich set of
different pcap files in their [archives](https://archive.wrccdc.org/) from various
competitions. I used their [2018 pcap data set](https://archive.wrccdc.org/pcaps/2018/) to
create my `even.json` files for personal use.

wrccdc 2018's [topology](https://archive.wrccdc.org/images/2018/wrccdc2018-topology.pdf) from their
competition is a close to real world scenario.

I also used the [Hands-on Network Forensics - Training PCAP dataset 2015](https://www.netresec.com/?page=PcapFiles)
from this [mirror](https://www.first.org/conference/2015/program#phands-on-network-forensics) and followed along with their [PDF guide](https://download.netresec.com/pcap/FIRST-2015/Hands-on_Network_forensics.pdf)

# How to download all the PCAPS from the 2018 competition

Use [wget](https://www.gnu.org/software/wget/)

```sh
wget -r -np -k https://archive.wrccdc.org/pcaps/2018/
```

This will download over a long period of time all the files to the sub-folder

```sh
archive.wrccdc.org/pcaps/2018
```

unzip those using gunzip

```sh
cd archive.wrccdc.org/pcaps/2018
gunzip *.gz
```

# How to make an alerts only configuration

Open your `suricata.yaml`

```sh
vim /usr/local/etc/suricata/suricata.yaml
```

And remove the sections of http, dns, tls, files, ssh, stats, and flow events. Also set your
stats to `enabled: false`. See [conf/suricata.yaml](conf/suricata.yaml) for my example.

# How to write a script to parse each file

See [scripts/ingest_pcap.sh](scripts/ingest_pcap.sh) for a simple for loop which will run suricata
and append to your eve.json file for each pcap file in a particular folder.

# SID allocations

For the signature lists see this page for the allocation of signature ids
https://doc.emergingthreats.net/bin/view/Main/SidAllocation

```
1000000-1999999 Reserved for Local Use -- Put your custom rules in this range to avoid conflicts

The following are the reservations for SIDs in the 2000000 space allocated to emerging threats:

2000000-2099999 Emerging Threats Open Rulesets

2100000-2103999 Forked ET Versions of the Original Snort GPL Signatures Originally sids 3464 and prior, forked to be maintained and converted to Suricata

2200000-2200999 Suricata Decoder Events

2210000-2210999 Suricata Stream Events

2220000-2299999 Suricata Reserved

2800000-2899999 Emerging Threats Pro Full Coverage Ruleset -- ETProRules

Dynamicly Updated Rules

2400000-2400999 SpamHaus DROP List — Updated Daily -- SpamHausDROPList

2402000-2402299 Dshield Top Attackers Rules — Updated Daily -- DshieldTopAttackers

2403300-2403499 CIArmy.com Top Attackers Rules — Updated Daily - See http://www.ciarmy.com#list -- CiArmy

2404000-2405999 Shadowserver.org Bot C&C List — Updated Daily -- BotCC

2404000-2405999 Shadowserver.org Bot C&C List Grouped by Port — Updated Daily -- BotCC

2406000-2406999 Russian Business Network Known Nets --- OBSOLETED -- RussianBusinessNetwork

2408000-2408499 Russian Business Network Known Malvertisers --- OBSOLETED -- RussianBusinessNetwork

2520000-2521999 Tor Exit Nodes List Updated Daily -- TorRules

2522000-2525999 Tor Relay Nodes List (NOT Exit nodes) Updated Daily -- TorRules
```

# Command line jq tips and tricks with a eve.json

Install [jq](https://stedolan.github.io/jq/) and go to a working directory that contains
an eve file.

```sh
cd /usr/local/var/log/suricata

# or from the releases zip you can use any of the eve.json
cd ./release/wrcddc-2018
cd ./release/first-org-conf-2015
```

To get all signatures from a eve.json

```sh
jq '.alert.signature' eve.json
```

This will return a list

```sh
"ET WEB_SERVER allow_url_include PHP config option in uri"
"ET WEB_SERVER safe_mode PHP config option in uri"
"ET WEB_SERVER suhosin.simulation PHP config option in uri"
"ET WEB_SERVER disable_functions PHP config option in uri"
"ET WEB_SERVER open_basedir PHP config option in uri"
```

To get a single sample signature id from a large `eve.json` using a sid (e.x. `2012647`)

```sh
jq 'select(.alert.signature_id==2012647)' eve.json | jq -s '.[0]'
```

To get a list of all uniq and sorted signature id's

```sh
jq 'select(.alert.signature_id)|.alert.signature_id' eve.json | sort | uniq
```

It will return sids sorted asc by number:

```sh
2001219
2001595
2001743
2002157
```

You can add that to an array like in a script

```sh
EVE_FILE=eve.json
SIGNATURES=(`jq 'select(.alert.signature_id)|.alert.signature_id' ${EVE_FILE} | sort | uniq`)
```

You can loop over that array to print a sample of each signature

```sh
EVE_FILE=eve.json
file_list=()
for SIGNATURE_ID in "${SIGNATURES[@]}"
do
  sample=`jq "select(.alert.signature_id==$SIGNATURE_ID)" ${EVE_FILE} | jq -s '.[0]'`
  file_list=("${file_list[@]}" "$sample")
done

echo "${file_list[@]}" | jq -s '.'
```

To sort a eve.json object of alerts by timestamp in ascending order:

```sh
jq -s 'sort_by(.timestamp)' eve.json
```

To get an ad-hoc timeline of signature strings from an eve.json file of all alerts:

```sh
jq -s 'sort_by(.timestamp)|.[].alert.signature' eve.json
```

To get an array of alerts in one of the sample sub-folders sorted by timestamp in ascending order:

```sh
cd ${ROOT_OF_THIS_PROJECT}
jq 'sort_by(.timestamp)' samples/first-org-conf-2015/alerts-only.json
```

To get an ad-hoc timeline of signature strings from one of the samples by timestamp:

```sh
cd ${ROOT_OF_THIS_PROJECT}
jq 'sort_by(.timestamp)|.[].alert.signature' samples/first-org-conf-2015/alerts-only.json
```
