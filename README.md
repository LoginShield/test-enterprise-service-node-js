test-enterprise-service-node-js
===============================

This service does NOT use a database; all data is stored in memory so
every time it starts the tests can be repeated.

To run the test service locally, you'll need to:

1. Follow directions in [Developer setup]
2. Set the [Environment variables]
3. Follow directions in [Start] for this service

In `package.json` you'll see this dependency:

```
    "@loginshield/realm-client-node": "^1.0.0",
```

The `@loginshield/realm-client-node` is part of the LoginShield Enterprise SDK,
and you can see how it is used `src/routes.js`.


# Developer setup

```
npm install
```

# Operation

## Environment variables

LISTEN_PORT
: where the service should accept connections
: an integer, e.g. `7101`
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
export LISTEN_PORT=7101
export ENDPOINT_URL=http://localhost
export LOGINSHIELD_ENDPOINT_URL=https://loginshield.com
export LOGINSHIELD_REALM_ID=xxxxxxxxxxxxxx
export LOGINSHIELD_AUTHORIZATION_TOKEN=yyyyyyyyyyyyyyyy
```

Windows PowerShell:

```
$env:LISTEN_PORT="7101"
$env:ENDPOINT_URL="http://localhost"
$env:LOGINSHIELD_ENDPOINT_URL="https://loginshield.com"
$env:LOGINSHIELD_REALM_ID="xxxxxxxxxxxxxx"
$env:LOGINSHIELD_AUTHORIZATION_TOKEN="yyyyyyyyyyyyyyyy"
```

## Start

```
npm start
```
