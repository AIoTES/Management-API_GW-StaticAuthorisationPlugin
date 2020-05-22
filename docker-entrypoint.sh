#!/bin/sh
#Script for accomodations of AIOTES integrations
#
#adjust file ownership
chown -R node:node /var/lib/eg/
#
#adjust Variable if needed
export EXTERNAL_ENDPOINT=$(echo $EXTERNAL_ENDPOINT | sed s/\:443//g )
echo "EXTERNAL_ENDPOINT="$(printenv EXTERNAL_ENDPOINT)
if [ -z ${NODE_ENVS+x} ]
then 
	NODE_ENVS="EXTERNAL_ENDPOINT="$(printenv EXTERNAL_ENDPOINT)
else 
	NODE_ENVS=${NODE_ENVS}" EXTERNAL_ENDPOINT="$(printenv EXTERNAL_ENDPOINT)
fi
NODE_ENVS=${NODE_ENVS}" LOG_LEVEL="$LOG_LEVEL
#
#wait until certificates are ready
echo "Waiting for certificates to be available"
while [ ! -f /var/lib/certs/live/aiotes/privkey.pem ]; do sleep 1; done
echo "privkey.pem found"
#
#check if certificates are self-signed
if [ -f "/var/lib/certs/live/aiotes/self-signed" ]
then
    echo "self-signed certificate detected"
    export NODE_EXTRA_CA_CERT=/var/lib/certs/live/aiotes/chain.pem
    echo "NODE_EXTRA_CA_CERT="$(printenv NODE_EXTRA_CA_CERT)
	NODE_ENVS=$NODE_ENVS" NODE_EXTRA_CA_CERT="$(printenv NODE_EXTRA_CA_CERT)
fi
#
#launch Express Gateway
echo "launching Express Gateway"
su -c "$NODE_ENVS node -e \"console.log(process.env);require('express-gateway')().run();\"" node
