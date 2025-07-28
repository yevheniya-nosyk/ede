# Extended DNS Errors

This repository contains all the code to set up test subdomains under extended-dns-errors.com. 

## Prerequisites

Start by copying the `.env-example` configuration file to `.env`, gradually filling it in as we set up the project. The copied file is ignored by Git. 

This project requires the following:

- a domain name to set up the testing infrastructure (`DOMAIN`)
- a VPS to serve the parent nameserver (`NS_PARENT_IP`, `NS_PARENT_USERNAME`)
- a VPS to serve the child nameserver (`NS_CHILD_IP`, `NS_CHILD_USERNAME`)
- an SSH key pair to connect to remote servers (`SSH_KEY_PRIVATE`)
- a web server to host the website under `DOMAIN` with both IPs (`A_RECORD`/`AAAA_RECORD`)

## Installation

### Docker

Follow the [official guidelines](https://docs.docker.com/engine/install/) on Docker installation. We need it installed on both nameservers and the main server where this project is being coordinated from.

To avoid running Docker with sudo, add your user to the `docker` group:

```bash
sudo usermod -a -G docker <username>
```

### Python3

Create the virtual environment and install the requirements:

```bash
$ python3 -m virtualenv -p python3 .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
```

## Subdomains configuration

The current list is stored in `subdomains.txt` with more detailed descriptions available on the project website. These need to be updated manually every time there is a change.

The script below does most of the configuration automatically, but prints the `DS` and `NS` records to be added to the registrar's control panel (this is for the parent domain only). If running it for the very first time, set the `CONFIGURE_NAMESERVERS` environment variable to True, so that the script sets up BIND9 on both parent and child: 

```bash
$ CONFIGURE_NAMESERVERS=true ./scripts/configure_subdomains.sh
```
