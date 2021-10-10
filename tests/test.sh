#!/bin/bash

######################### Run Good Tests #########################

# there isn't a firewall-policies-good.pol in this version of the project

## Cleanup first
#sudo ../cleanup.sh >> /dev/null 2>&1
#
## Setup the Empty Firewall
#pushd .. >> /dev/null 2>&1
#./run-firewall.sh firewall-policies-good.pol >> /dev/null 2>&1 &
#popd >> /dev/null 2>&1
#
## Delay the start
#sleep 1
#
## Run the Pre Unit Tests
#echo "Running the control tests against firewall-policies-good.pol"
#sudo python -m unittest test_policy_good

######################### Run Assignment Tests #########################

# Cleanup again
sudo ../cleanup.sh >> /dev/null 2>&1

# Setup the Your Firewall
pushd .. >> /dev/null 2>&1
echo '***** running first start-firewall.sh *****'
./start-firewall.sh configure.pol >> /dev/null 2>&1 &
echo '***** DONE running first start-firewall.sh *****'
popd >> /dev/null 2>&1

# Delay the start to wait for the firewall
sleep 5

# Run the Unit Tests
echo "Running the tests against configure.pol to test rules given in project"
sudo python -m unittest test_config_policy
sudo ../cleanup.sh >> /dev/null 2>&1

######################### Run Other Tests #########################

# Cleanup again
sudo ../cleanup.sh >> /dev/null 2>&1

# Setup the Your Firewall
pushd .. >> /dev/null 2>&1
./start-firewall.sh tests/firewall-policies-other.pol >> /dev/null 2>&1 &
popd >> /dev/null 2>&1

# Delay the start
sleep 1

# Run the Unit Tests
echo "Running the tests against firewall-policies-other.pol"
sudo python -m unittest test_other

# Cleanup last
sudo ../cleanup.sh >> /dev/null 2>&1
