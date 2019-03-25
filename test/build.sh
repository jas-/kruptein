#!/bin/bash -x

# Build nodejs against libressl for additional testing


# LibreSSL URI
libressl_uri="https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/"

# nodejs URI
nodejs_uri="https://nodejs.org/download/release/"


# Handle acquisition & extraction of libressl (latest version)
function get_libressl() {
  
  # Aquire a list of version available
  local -a libressl_versions
  libressl_versions=($(curl ${libressl_uri} 2>/dev/null |
    awk '$2 ~ /libressl-.*tar.gz/ && $2 !~ /.asc/{gsub(/href=".*">|<\/a>/, "", $2);print $2}' |
    sort -V))

  # Bail if ${#libressl_versions[@]} is empty
  if [ ${#libressl_versions[@]} -eq 0 ]; then
    echo "Unable to acquire libressl versions, bailing"
    exit 1
  fi

  libressl_version="${libressl_versions[${#libressl_versions[@]}-1]}"

  # Get the last value from the ${libressl_versions[@]} array & build a URI
  libressl_uri="${libressl_uri}${libressl_version}"
  
  # Fetch and extract ${libressl_uri}
  curl ${libressl_uri} 2>/dev/null | tar -zxf - 2>/dev/null

  # If local folder doesn't exist bail on failed download/extract
  if [ ! -d "${libressl_version}" ]; then
    echo "Unable to download and/or extract ${libressl_uri}, bailing"
    exit 1
  fi
}


# Handle acquisition & extraction of nodejs based on TRAVIS_CI version of testing
function get_nodejs() {

  # Acquire a list of versions available >= v4
  local -a nodejs_versions
  node_versions=($(curl ${nodejs_uri} 2>/dev/null |
    awk '$2 !~ /.tar.gz|index|versions|or|of|latest|patch|npm/{gsub(/href=".*">|<\/a>/, "", $2);print $2}' |
    sort -V | awk -F"." '$2 >= 4' | sed 's/\///g'))

  # Bail if ${#nodejs_versions[@]} is empty
  if [ ${#nodejs_versions[@]} -eq 0 ]; then
    echo "Unable to acquire nodejs versions, bailing"
    exit 1
  fi


  # Get the current environment from Travis-CI
  nodejs_version=$TRAVIS_NODE_VERSION

  # Bail if ${nodejs_version} isn't set
  if [ ${nodejs_version:=0} -eq 0 ]; then
    echo "Unable to determine target nodejs version, bailing"
    exit 1
  fi


  # Since we have a ${nodejs_version} pluck it from our ${node_versions[@]} array
  nodejs="$(echo "${node_versions[@]}" | tr ' ' '\n' |
    grep "^v${nodejs_version}" | sort -V | tail -1)"

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
  if [ ! -d "node-${nodejs}" ]; then
    echo "Unable to download and/or extract ${nodejs_uri}, bailing"
    exit 1
  fi
}


# Download & extrace libressl
get_libressl
