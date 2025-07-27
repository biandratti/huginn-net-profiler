#!/bin/bash
# A simple deployment script for Huginn

# Check if the network interface parameter is provided
if [ -z "$1" ]; then
    echo "Error: Network interface must be provided as the first argument."
    echo "Usage: $0 <network-interface>"
    exit 1
fi

export NETWORK_INTERFACE=$1

echo "Downloading JA4 database..."
curl -sL https://ja4db.com/api/download/ > ja4_database.json
echo "Database downloaded."

echo "Starting deployment with network interface: $NETWORK_INTERFACE"

docker-compose up -d --force-recreate

echo "Deployment finished. Application is running."
