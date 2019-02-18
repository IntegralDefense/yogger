#!/bin/bash
# install required packages
sudo apt-get update
sudo apt-get install python3-pip

# install python packages
sudo -H -E pip3 install ConfigParser yara-python requests 

# ignore changes to config.ini
git update-index --assume-unchanged config/config.ini

# create all required directories
if [ ! -d "logs" ]; then
	mkdir "logs"
fi

# clone indicators
echo -n "Indicator repo (e.g. git@github.com:user_name:indicators.git): "
read repo
git clone $repo indicators

# install cron jobs
(crontab -l ; cat setup/cronjobs)| crontab -

# install service configuration
sudo cp setup/yogger.service /etc/systemd/system/yogger.service

# enabled starting yogger on system boot
sudo systemctl enable yogger
