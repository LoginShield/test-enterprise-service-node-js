Enterprise Test Service
=======================

# Developer setup

```
npm install
```

If you are also working on `gateway-core-js` and `gateway-node-js`:

```
( cd gateway-core-js && npm link )
( cd gateway-node-js && npm link )
```

```
cd service-gateway-proxy-nodejs
npm link @loginshield/gateway-core
```

# Operation

## Environment variables

PORT
: where the service should accept connections
: an integer, e.g. `7100`
: required

ENDPOINT_URL
: used to generate HTTP redirects to this service
: an absolute URL, e.g. `https://example.com/path`
: required for LoginShield integration, but will not prevent service from starting
: value must match the "domain" defined for the realm at the authentication service
  (e.g. `example.com`)

LOGINSHIELD_ENDPOINT_URL
: used to generate HTTP redirects to this service
: an absolute URL, e.g. `https://example.com/path`
: required for LoginShield integration, but will not prevent service from starting
: value must match the "domain" defined for the realm at the authentication service
  (e.g. `example.com`)

LOGINSHIELD_REALM_ID
: issued by authentication service
: required for LoginShield integration, but will not prevent service from starting

LOGINSHIELD_AUTHORIZATION_TOKEN
: issued by authentication service
: required for LoginShield integration, but will not prevent service from starting

Linux:

```
export PORT=7100
export ENDPOINT_URL=http://localhost:7100
export LOGINSHIELD_ENDPOINT_URL=https://loginshield.com
export LOGINSHIELD_REALM_ID=xxxxxxxxxxxxxx
export LOGINSHIELD_AUTHORIZATION_TOKEN=yyyyyyyyyyyyyyyy
```

Windows PowerShell:

```
$env:PORT="7100"
$env:ENDPOINT_URL="http://localhost:7100"
$env:LOGINSHIELD_ENDPOINT_URL="https://loginshield.com"
$env:LOGINSHIELD_REALM_ID="xxxxxxxxxxxxxx"
$env:LOGINSHIELD_AUTHORIZATION_TOKEN="yyyyyyyyyyyyyyyy"
```

## Persistence

This service does NOT use a database; all data is stored in memory so
every time it starts the tests can be repeated.

## Start

```
npm start
```


