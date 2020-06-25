#!/bin/bash

sudo ufw deny out from 10.0.2.7 to 10.0.2.8 port 23
sudo ufw deny in from 10.0.2.8 to 10.0.2.7 port 23
sudo ufw deny out to 64.35.176.173
sudo ufw status

