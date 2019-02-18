# Yogger - Yara Scanner for Logstash Logs
Yogger is a systemd service for scanning logstash logs with yara rules

## Installation
Clone the repo and run the setup script.
```bash
git@github.com:IntegralDefense/yogger.git
cd yogger
./setup.sh
```

Add an entry for saq_aggregator to your /etc/hosts file
###### Example /etc/hosts file
```
127.0.0.1 saq_aggregator
```

## Running Yogger
```bash
# start yogger
sudo systemctl start yogger

# stop yogger
sudo systemctl stop yogger
```

