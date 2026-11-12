#!/bin/sh
set -eu
node /lab/verify.js "$STRAPI_VERSION" /dependencies
mkdir -p /tmp/strapi
cp -R /lab/app/. /tmp/strapi/
cp /dependencies/package.json /tmp/strapi/package.json
ln -s /dependencies/node_modules /tmp/strapi/node_modules
cd /tmp/strapi
exec node server.js
