/* eslint-disable */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookie = require('cookie');
const { URL } = require('url');
const { routes } = require('./routes');
const { Database } = require('./database');

const {
  LISTEN_PORT,
    } = process.env;

// validate configuration settings
let isConfError = false;
['LISTEN_PORT'].forEach((item) => {
  if(!process.env[item]) {
    console.error(`environment variable is required: ${item}`);
    isConfError = true;
  }
});
if(isConfError) {
  process.exit(1);
}

// in-memory database
const database = new Database();

// configure express framework
const expressApp = express();
expressApp.set('trust proxy', true);
expressApp.set('query parser', 'simple');
expressApp.set('x-powered-by', false);
expressApp.use(helmet());

// make configuration available to request processing functions
// in req.app.locals.config
expressApp.locals = {
    database,
    config: {
    }
};

routes(expressApp);

// express listen
const server = expressApp.listen(LISTEN_PORT);

console.log('http service started on port %s', LISTEN_PORT);

['SIGINT', 'SIGTERM', 'SIGQUIT']
  .forEach(signal => process.on(signal, async () => {
      // shutdown express server
      server.close(() => {
        console.log('Http server closed.');
        process.exit();
      });
  }));

