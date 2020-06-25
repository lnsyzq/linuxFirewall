#!/bin/bash

sudo ufw deny from 10.0.2.8 to 10.0.2.7 port 22
sudo ufw deny from 10.0.2.8 to 10.0.2.7 port 80
sudo ufw status

