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

ENDPOINT_URL
: used to generate HTTP redirects
: an absolute URL, e.g. `https://example.com/path`

PORT
: where the service should accept connections
: an integer, e.g. `7100`

SECURE_KEY
: used to encrypt cookie values
: a comma-separated list of one or more keys
: each key is 16 bytes, hex-encoded (32 characters)
: the first key is used to encrypt new cookies
: subsequent keys used only to decrypt older cookies

Linux:

```
export ENDPOINT_URL=http://localhost:7100
export PORT=7100
export SECURE_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Windows PowerShell:

```
$env:CHALLENGE_ENDPOINT_URL="http://localhost:7504/service/login/challenge"
$env:PUSH_ENDPOINT_URL="http://localhost:7504/service/login/push"
$env:SHARE_ENDPOINT_URL="http://localhost:7504/mx/share"
$env:PORT="7100"
$env:SECURE_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
```

## Persistence

This service does NOT use a database; all data is stored in memory so
every time it starts the tests can be repeated.

## Start

```
npm start
```


