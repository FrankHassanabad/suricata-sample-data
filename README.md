# suricata-sample-data

This is a project and repository of different outputs of Suricata run against different
[pcap](https://en.wikipedia.org/wiki/Pcap) data sets. You can download the Suricata data
sets from the releases page of this repository.

[Alerts only zip](https://github.com/FrankHassanabad/suricata-sample-data/releases/download/v1.0.0/eve-alerts-only-wrccdc.zip)

Optionally you can read below on how to create your own data sets from your own
[pcap](https://en.wikipedia.org/wiki/Pcap) files just like I did.

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

The pcaps I found most interesting for rich data was the
[The Western Regional Cyber Defense 2018 (wrccdc)](http://www.wrccdc.org/). wrccdc has a rich set of
different pcap files in their [archives](https://archive.wrccdc.org/) from various
competitions. I used their [2018 pcap data set](https://archive.wrccdc.org/pcaps/2018/) to
create my `even.json` files for personal use.

wrccdc 2018's [topology](https://archive.wrccdc.org/images/2018/wrccdc2018-topology.pdf) from their
competition is a close to real world scenario.

![topology](img/wrccdc2018-topology.png?raw=true)

# How to download all the PCAPS from the competition

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
and output your eve.json file (/usr/local/var/log/suricata/eve.json) on each pcap file in a particular folder.
