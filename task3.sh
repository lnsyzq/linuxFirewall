#!/bin/bash

sudo ufw deny out 23
sudo ufw deny out to 64.35.176.173
sudo ufw status
