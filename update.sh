#!/bin/bash

go build .
sudo systemctl stop edgenet.service
sudo cp node /opt/edgenet/
sudo systemctl start edgenet.service

sudo cat /var/log/syslog
