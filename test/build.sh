#!/usr/bin/env bash

# Build nodejs against libressl for additional testing


# nodejs URI
nodejs_uri="https://nodejs.org/download/release/"

# Acquire a list of versions available >= v4
declare -a nodejs_versions
node_versions=($(curl ${nodejs_uri} 2>/dev/null |
  awk '$2 !~ /.tar.gz|index|versions|or|of|latest|patch|npm/{gsub(/href=".*">|<\/a>/, "", $2);print $2}' |
  sort -V | awk -F"." '$2 >= 4'))


# Get the current environment from Travis-CI
nodejs_version=$TRAVIS_NODE_VERSION

# Bail if ${nodejs_version} isn't set
if [ ${nodejs_version:=0} -eq 0 ]; then
  echo "Unable to determine target nodejs version, bailing"
  exit 1
fi


# Since we have a ${nodejs_version} pluck it from our ${node_versions[@]} array
nodejs="$(echo "${node_version[@]}" | tr ' ' '\n' | grep "^${nodejs_version}")"

# Bail if ${nodejs} wasn't found
if [ ${nodejs:=0} -eq 0 ]; then
  echo "Unable to determine target nodejs URI, bailing"
  exit 1
fi


# Set ${nodejs_uri} to ${nodejs} and file
nodejs_uri="${nodejs_uri}/${nodejs}/node-${nodejs}.tar.gz"


# Fetch and extract ${nodejs_uri}
curl ${nodejs_uri} 2>/dev/null | tar -zxf - 2>/dev/null

# If local folder doesn't exist bail on failed download/extract
if [ ! -d ${nodejs} ]; then
  echo "Unable to download and/or extract ${nodejs_uri}, bailing"
  exit 1
fi


