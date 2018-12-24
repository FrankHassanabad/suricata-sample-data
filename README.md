# suricata-sample-data

Repository of creating different example suricata data sets

[Suricata](https://suricata-ids.org/) is a engine is capable of real
time intrusion detection (IDS), inline intrusion prevention (IPS), network
security monitoring (NSM) and offline pcap processing.

This repository contains sample eve log data sets created by Suricata from
existing [pcap](https://en.wikipedia.org/wiki/Pcap) files as well as instructions
on how to create them yourself. This is useful if you want to see what alerts
_only_ data sets look like or play with the rules yourself and re-create your
own [eve](https://suricata.readthedocs.io/en/suricata-3.2.1/output/eve/eve-json-output.html)
files for learning purposes to write your own `eve.json` real time simulator.

The pcaps I found most interesting for good data was the
[The Western Regional Cyber Defense 2018](http://www.wrccdc.org/). They have a rich set of
different pcap files in their [archives](https://archive.wrccdc.org/) from various
competitions. I used their [2018 pcap data set](https://archive.wrccdc.org/pcaps/2018/) to
create my `even.json` files for download.

Their [topology](https://archive.wrccdc.org/images/2018/wrccdc2018-topology.pdf) from their
competition looks to be a close to real world scenario which makes the captured pcap files
rich when during the competition where red teams attack it at the same time their blue teams are using the system.

![topology](img/wrccdc2018-topology.png?raw=true)
