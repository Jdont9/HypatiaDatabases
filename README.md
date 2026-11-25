# Hypatia Databases
This repository contains the database files, the generation scripts and the web server for the malware databases used in the FOSS android antivirus [Hypatia](https://github.com/MaintainTeam/Hypatia).
## Structure
This is a manual mirror and backup generator of https://codeberg.org/MaintainTeam/HypatiaDatabases which generates the default databases.

This repo has several branches. The `main` branch contains the [code](.github/workflows/generate_stable.yml) used to generate the databases. The `unsigned` branch contains the generated databases, before they are signed. From here, this branch is checked out by a self-hosted CI and signed with our key, and pushed to the `gh-pages` branch where it is deployed.
## Databases
### General Sources
- [ESET Indicators of Compromise (IOC's)](https://github.com/eset/malware-ioc)
- [ThreatView Malware Databases](https://threatview.io/)
- [ThreatFox](threatfox.abuse.ch)
- [Malware Bazzar](https://bazaar.abuse.ch/)
- [CyberCure](https://www.cybercure.ai/)
- [SaneSecurity](https://sanesecurity.com/)
- [Signature Base](https://github.com/Neo23x0/signature-base)
- [MalShare](https://malshare.com/) (API, accumulated daily; needs the `MALSHARE_KEY` secret)
- [Zscaler ThreatLabz IOCs](https://github.com/threatlabz/iocs) (MIT)
### Specific Sources
- [Stalkerware IOCs](https://github.com/AssoEchap/stalkerware-indicators) (sample hashes in the signature databases, plus package names and signing certificates in `hypatia-stalkerware-bloom.bin`, see `tools/stalkerware_indicators.py`)
- [Covid-19 IOCs](https://github.com/avast/covid-19-ioc)
- [Citizen Lab malware indicators](https://github.com/citizenlab/malware-indicators) (CC BY-NC-SA 4.0)
### Domain Sources
- Divested Computing Group's [Domain Blocklists](https://divested.dev/pages/dnsbl)
- [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (active phishing domains, filtered by the allowlist below)
- [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists)
- [URLhaus hostfile](https://urlhaus.abuse.ch/api/) (abuse.ch)

Extra domain sources (HaGeZi, Phishing.Database, URLhaus, MVT, Avast, Infosec, Citizen Lab) are filtered against an allowlist (Tranco top 10k + MISP warninglists) before being merged. The Divest list is not filtered.
## Generation
The databases are generated on GitHub's and Codeberg's CI. We utilize a fork of Divest Mobile's [database generator](./src/main/java/org/maintainteam/hypatiadatabases/App.java) to sort the database files, aggregate the hashes, and then create Bloom Filters from them. Then, GitHub/Codeberg Pages are used to publish the files online.
## Anti-rollback manifest
Every database file is signed on its own, so an attacker could replay an old set of files that still carry valid signatures. To prevent it, each generation also publishes a signed manifest (`tools/build_manifest.py`): `hypatia-manifest.txt` (+ `.sig`) for the stable databases and `hypatia-extended-manifest.txt` (+ `.sig`) for the extended one. It holds a `sequence` number (UTC epoch seconds of the generation) and the SHA-256 of every database file. The app refuses a manifest older than the last one it accepted and any database file that does not match the manifest. Both manifests are signed by the same step as the databases (binary `.sig`, same key). Servers that do not publish a manifest keep working, but once a server has published one the app no longer accepts its absence.

## Contribution
**Development work is done on GitHub, Codeberg is only a mirror.**

We are always looking for new sources to add to our databases, so if you come across one that you believe could work, please either create an issue with the link to the source, and it's copyright, or if you can, submit a pull request to add it to the GitHub actions file. 

If adding a new source, the general proccess is:
1. Download the source to the `/various/vendor` directory.
2. Proccess the file(s) to extract the hashes, and if applicable the malware description.
3. Combine the name and hash (`hash:0:name/description`) and add them to a file with the appropriate extension.
4. Move the resulting file to the `/raw/vendor` directory.
