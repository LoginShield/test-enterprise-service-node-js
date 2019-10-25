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
    PORT,
    } = process.env;

// validate configuration settings
assert(PORT, 'process.env.PORT required');

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
const server = expressApp.listen(PORT);

console.log('http service started on port %s', PORT);

['SIGINT', 'SIGTERM', 'SIGQUIT']
  .forEach(signal => process.on(signal, async () => {
      // shutdown express server
      server.close(() => {
        console.log('Http server closed.');
        process.exit();
      });
  }));

