const fs = require('fs');
const { strict: assert } = require('assert');
const cookie = require('cookie');
const { Router, json } = require('express');
const bodyParser = require('body-parser');
const { compact } = require('./input');
const { randomHex } = require('./random');
const pkg = require('../package.json');
const crypto = require('crypto');

const COOKIE_NAME = 'test';

function setNoCache (req, res, next) {
  res.set('Pragma', 'no-cache')
  res.set('Cache-Control', 'no-cache, no-store')
  next()
}

async function session(req, res, next) {
  const { database } = req.app.locals;
  let sessionId, session;
  const cookieHeader = req.get('Cookie');
  if( cookieHeader ) {
    const cookieMap = cookie.parse(cookieHeader);
    sessionId = cookieMap[COOKIE_NAME];  
  }
  if(sessionId) {
    session = await database.collection("session").fetchById(sessionId);
  }
  if(!sessionId || !session || typeof session !== 'object') {
      // create a new session
      sessionId = randomHex(16);
      session = {};
      await database.collection("session").create(sessionId, session);
  }
  // make session content available to routes
  req.session = session;
  // set or update the cookie to expire after 90 days
  const seconds = 7776000; // 86400 seconds in 1 day * 90 days
  const expiresMillis = Date.now() + (seconds * 1000);
  res.cookie(COOKIE_NAME, sessionId, {
    // ask browser to...
    maxAge: seconds, // keep cookie for this many seconds (for standards-compliant browsers)
    expires: new Date(expiresMillis), // or keep cookie until this date (for old browsers, should be ignored by browsers that use max-age)
    httpOnly: true, // do not disclose cookie to javascript or extensions unless user grants secure cookie permissions
    secure: process.env.NODE_ENV === 'production', // only send the cookie with https requests
  });  
  // listen for end of request processing to store session info
  res.on('finish', async function() {
    // store session data
    await database.collection("session").editById(sessionId, req.session);
  });
  next();
}

async function httpGetVersion(req, res) {
  return res.json({name: pkg.name, version: pkg.version});
}
async function httpGetContext(req, res) {
  return res.json({});
}

async function httpGetSession(req, res) {
  const { isAuthenticated, userId } = req.session;
  if(isAuthenticated && userId) {
    return res.json({isAuthenticated: true});
  }
  return res.json({isAuthenticated: false});
}

async function httpPostLogout(req, res) {
  req.session.isAuthenticated = false;
  req.session.userId = null;
  return res.json({isAuthenticated: false});
}

async function httpGetAccount(req, res) {
  const { database } = req.app.locals;
  if(req.session.isAuthenticated && req.session.userId) {
    const account = await database.collection("user").fetchById(req.session.userId);
    if(account) {
      const {username,email,loginshield: {isRegistered, isEnabled}} = account;
      return res.json({username,email,loginshield: {isRegistered, isEnabled}});
    }
  }
  return res.json({error: 'unauthorized'});
}

async function httpPostRegister(req, res) {
  const { database } = req.app.locals;
  console.log('register request: %o', req.body);
  const { username, email, password} = req.body;
  const userId = randomHex(16);
  const salt = randomHex(8);
  const sha256 = crypto.createHash('sha256');
  sha256.update(salt);
  sha256.update(password);
  const hash = sha256.digest('hex');
  await database.collection("user").create(userId, {
    username,
    email,
    password: {salt, hash},
    loginshield: {isRegistered: false, isEnabled: false}
  });
  await database.collection("map_username_to_id").create(username, {id: userId});
  req.session.isAuthenticated = true;
  req.session.userId = userId;
  return res.json({isCreated: true});
}

async function httpPostLogin(req, res) {
  const { database } = req.app.locals;
  console.log('login request: %o', req.body);
  const { username, password } = req.body;
  const result = await database.collection("map_username_to_id").fetchById(username);
  if(result) {
    const userId = result.id;
    if(userId) {
      const user = await database.collection("user").fetchById(userId);
      if(user) {
        const sha256 = crypto.createHash('sha256');
        sha256.update(user.password.salt);
        sha256.update(password);
        const hash = sha256.digest('hex');      
        if(hash === user.password.hash) {
          req.session.isAuthenticated = true;
          req.session.userId = userId;
          return res.json({isAuthenticated: true});
        }
      }
    }
  }
  req.session.isAuthenticated = false;
  req.session.userId = null;
  return res.json({isAuthenticated: false});
}

function routes(app) {
  const routes = new Router();
  routes.use(setNoCache);
  routes.use(bodyParser.json());
  routes.use(session);

  // service info
 routes.get('/version', httpGetVersion);
 routes.get('/context', httpGetContext);
 // session management
 routes.get('/session', httpGetSession);
 routes.post('/session/login', httpPostLogin);
 routes.post('/session/logout', httpPostLogout);
 // account management
 routes.get('/account', httpGetAccount);
 routes.post('/account/register', httpPostRegister);

  routes.use((err, req, res, next) => {
      if( err ) {
        res.status(500);
          return res.json({error: 'server-error'});
      }
      return next(err);
  })

  app.use('/', routes);
}

module.exports = { routes };
