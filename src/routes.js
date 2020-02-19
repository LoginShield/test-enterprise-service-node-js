const { RealmClient } = require('@cryptium/tigercomet-realm-client-node');
const { randomHex } = require('@cryptium/util-random-node');
// const { strict: assert } = require('assert');
const bodyParser = require('body-parser');
const cookie = require('cookie');
const crypto = require('crypto');
const { Router /* , json */ } = require('express');
const pkg = require('../package.json');

const COOKIE_NAME = 'test';

function setNoCache(req, res, next) {
    res.set('Pragma', 'no-cache');
    res.set('Cache-Control', 'no-cache, no-store');
    next();
}

async function session(req, res, next) {
    const { database } = req.app.locals;
    let sessionId = null;
    let sessionInfo = {};
    const cookieHeader = req.get('Cookie');
    if (cookieHeader) {
        const cookieMap = cookie.parse(cookieHeader);
        sessionId = cookieMap[COOKIE_NAME];
    }
    if (sessionId) {
        sessionInfo = await database.collection('session').fetchById(sessionId);
    }
    if (!sessionId || !sessionInfo || typeof sessionInfo !== 'object') {
        // create a new session
        sessionId = randomHex(16);
        sessionInfo = { userId: null, notAfter: null };
        await database.collection('session').insert(sessionId, sessionInfo);
    }
    // make session content available to routes
    req.session = sessionInfo;
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
    res.on('finish', async () => {
    // store session data
        await database.collection('session').editById(sessionId, req.session);
    });
    next();
}

function isSessionAuthenticated({ userId, notAfter } = {}) {
    return userId && typeof notAfter === 'number' && Date.now() <= notAfter;
}

async function httpGetVersion(req, res) {
    return res.json({ name: pkg.name, version: pkg.version });
}
async function httpGetContext(req, res) {
    return res.json({});
}

async function httpGetSession(req, res) {
    const isAuthenticated = isSessionAuthenticated(req.session);
    return res.json({ isAuthenticated });
}

async function httpPostLogout(req, res) {
    req.session.userId = null;
    req.session.notAfter = null;
    return res.json({ isAuthenticated: false });
}

async function httpGetAccount(req, res) {
    const { database } = req.app.locals;
    const isAuthenticated = isSessionAuthenticated(req.session);
    if (isAuthenticated) {
        const account = await database.collection('user').fetchById(req.session.userId);
        if (account) {
            const { username, email, loginshield: { isRegistered, isEnabled } } = account;
            return res.json({ username, email, loginshield: { isRegistered, isEnabled } });
        }
    }
    return res.json({ error: 'unauthorized' });
}

async function httpPostCreateAccount(req, res) {
    const { database } = req.app.locals;
    console.log('httpPostCreateAccount request: %o', req.body);
    const { username, email, password } = req.body;
    // validate inputs
    if(typeof username !== 'string' || username.trim().length === 0) {
        console.log('httpPostCreateAccount: non-empty username is required');
        return res.json({ isCreated: false, error: 'username-required' });
    } 
    if(typeof email !== 'string' || email.trim().length === 0) {
        console.log('httpPostCreateAccount: non-empty email is required');
        return res.json({ isCreated: false, error: 'email-required' });
    }
    if(typeof password !== 'string' || password.trim().length === 0) {
        console.log('httpPostCreateAccount: non-empty password is required');
        return res.json({ isCreated: false, error: 'password-required' });
    } 
    // check if user already exists
    const lcUsername = username.toLowerCase();
    const result = await database.collection('map_username_to_id').fetchById(lcUsername);
    if (result && result.id) {
        return res.json({ isCreated: false });
    }
    const userId = randomHex(16);
    const salt = randomHex(8);
    const sha256 = crypto.createHash('sha256');
    sha256.update(salt);
    sha256.update(password);
    const hash = sha256.digest('hex');
    await database.collection('user').insert(userId, {
        username: lcUsername,
        email,
        password: { salt, hash },
        loginshield: { isRegistered: false, isEnabled: false },
    });
    await database.collection('map_username_to_id').insert(lcUsername, { id: userId });
    const seconds = 900; // 60 seconds in 1 minute * 15 minutes
    const expiresMillis = Date.now() + (seconds * 1000);
    req.session.userId = userId;
    req.session.notAfter = expiresMillis;
    return res.json({ isCreated: true });
}

function isAuthenticatedWithPassword(user, password) {
    const sha256 = crypto.createHash('sha256');
    sha256.update(user.password.salt);
    sha256.update(password);
    const hash = sha256.digest('hex');
    return hash === user.password.hash;
}

async function httpPostLogin(req, res) {
    // login process starts with a non-authenticated session
    req.session.userId = null;
    req.session.notAfter = null;
    const { database } = req.app.locals;
    console.log('login request: %o', req.body);
    const { username } = req.body;
    if (typeof username !== 'string' || username.trim().length === 0) {
        console.log('httpPostLogin: non-empty username is required');
        return res.json({ error: 'username-required' });
    }
    const lcUsername = username.toLowerCase();
    const result = await database.collection('map_username_to_id').fetchById(lcUsername);
    if (result && result.id) {
        const userId = result.id;
        const user = await database.collection('user').fetchById(userId);
        if (user) {
            // respond with required authentication method
            if (user.loginshield.isEnabled && user.loginshield.userId) {
                return res.json({ isAuthenticated: false, mechanism: 'loginshield' });
            }
            if (user.password) {
                return res.json({ isAuthenticated: false, mechanism: 'password' });
            }
        }
    }
    // for unknown username,
    // return the same response to prevent user enumeration
    // for password-protected accounts
    return res.json({ isAuthenticated: false, mechanism: 'password' });
}

async function httpPostLoginWithPassword(req, res) {
    req.session.userId = null;
    req.session.notAfter = null;
    const { database } = req.app.locals;
    console.log('httpPostLoginWithPassword request: %o', req.body);
    const { username, password } = req.body;
    if (typeof username !== 'string' || username.trim().length === 0) {
        console.log('httpPostLoginWithPassword: non-empty username is required');
        return res.json({ isAuthenticated: false, error: 'username-required' });
    }
    if (typeof password !== 'string' || password.trim().length === 0) {
        console.log('httpPostLoginWithPassword: non-empty password is required');
        return res.json({ isAuthenticated: false, error: 'password-required' });
    }
    const lcUsername = username.toLowerCase();
    const result = await database.collection('map_username_to_id').fetchById(lcUsername);
    if (result && result.id) {
        const userId = result.id;
        const user = await database.collection('user').fetchById(userId);
        if (user) {
            // respond with required authentication method
            if (user.loginshield.isEnabled) {
                return res.json({ isAuthenticated: false, error: 'loginshield-required' });
            }
            if (user.password && password && isAuthenticatedWithPassword(user, password)) {
                // loginshield not enabled, and password was submitted
                const seconds = 900; // 60 seconds in 1 minute * 15 minutes
                const expiresMillis = Date.now() + (seconds * 1000);
                req.session.userId = userId;
                req.session.notAfter = expiresMillis;
                return res.json({ isAuthenticated: true });
            }
        }
    }
    // for unknown username, or incorrect password,
    // return the same response to prevent user enumeration
    // for password-protected accounts
    return res.json({ isAuthenticated: false });
}

async function httpPostLoginWithLoginShield(req, res) {
    const { database } = req.app.locals;
    const { ENDPOINT_URL, LOGINSHIELD_REALM_ID } = process.env;
    console.log('httpPostLoginWithLoginShield request: %o', req.body);
    const { username, mode, verifyToken } = req.body;
    // to initiate a login, parameters are username (required), mode (optional)
    // to complete a login, parameters are token (required)
    if (verifyToken) {
        const loginshield = new RealmClient();
        const verifyLoginResponse = await loginshield.verifyLogin(verifyToken);
        if (verifyLoginResponse.error || verifyLoginResponse.fault) {
            return { isAuthenticated: false };
        }
        // TODO: the report includes the authorization certificate, we could parse it, extract the challenge, check the realm id in the challenge equals our realm id and equals the realm id mentioned in the report, check the realm scoped user id in the challenge is equal to realm scoped user id mentioned in the report, check that the public key that verifies the authorization certificate matches the public key stored for the user, check dates, nonce, etc.; these are all things that loginshield already verifies and provides the proof so the verification can be repeated here immediately or later in an audit
        // TODO: we could check that the session that started the login for the realmscopeduserid is the same one that
        // started the login, to prevent anyone from stealing a token for a process they didn't start; loginshield already
        // verifies its the same client, but we could also do the same check
        if (verifyLoginResponse.realmId === LOGINSHIELD_REALM_ID) {
        // we need to lookup the username by realmScopedUserId OR we need to know the original token we sent with the user, so we can lookup the username there, because that's how the whole thing started anyway
            const existingUserId = await database.collection('map_loginshielduserid_to_id').fetchById(verifyLoginResponse.realmScopedUserId);
            if (existingUserId) {
                const user = await database.collection('user').fetchById(existingUserId);
                if (user) {
                    if (user.loginshield && !user.loginshield.isEnabled) {
                        const loginWithLoginShield = {
                            isEnabled: true,
                            isRegistered: true,
                            userId: verifyLoginResponse.realmScopedUserId,
                        };
                        await database.collection('user').editById(existingUserId, { loginshield: loginWithLoginShield });
                    }
                    const seconds = 900; // 60 seconds in 1 minute * 15 minutes
                    const expiresMillis = Date.now() + (seconds * 1000);
                    req.session.userId = existingUserId;
                    req.session.notAfter = expiresMillis;
                    return res.json({ isAuthenticated: true });
                }
            }
        }
        // token provided but not validated
        return res.json({ isAuthenticated: false });
    }
    if (typeof username !== 'string' || username.trim().length === 0) {
        console.log('httpPostLoginWithLoginShield: non-empty username is required');
        return res.json({ isAuthenticated: false, error: 'username-required' });
    }
    const lcUsername = username.toLowerCase();
    const result = await database.collection('map_username_to_id').fetchById(lcUsername);
    if (result && result.id) {
        const userId = result.id;
        const user = await database.collection('user').fetchById(userId);
        if (user) {
            // respond with required authentication method
            if (user.loginshield.isEnabled && user.loginshield.userId) {
                const loginshield = new RealmClient();
                const startLoginResponse = await loginshield.startLogin({ realmScopedUserId: user.loginshield.userId, redirect: `${ENDPOINT_URL}/login?mode=resume-loginshield` });
                console.log('got startLoginResponse: %o', JSON.stringify(startLoginResponse));
                return res.json({
                    isAuthenticated: false,
                    forward: startLoginResponse.forward,
                });
            }
            const isAuthenticated = isSessionAuthenticated(req.session);
            if (isAuthenticated && mode === 'activate-loginshield') {
                // user must already be registered with loginshield and have a realm-scoped-user-id
                if (!user.loginshield.userId) {
                    console.log('loginshield registration required before login');
                    return res.json({ isAuthenticated: false, error: 'registration-required' });
                }
                // we indicate in the start login request that this login is for completing
                // the realm user registration process
                const loginshield = new RealmClient();
                const startLoginResponse = await loginshield.startLogin({ realmScopedUserId: user.loginshield.userId, isNewKey: true, redirect: `${ENDPOINT_URL}/login?mode=resume-loginshield` });
                console.log('got startLoginResponse: %o', JSON.stringify(startLoginResponse));
                return res.json({
                    isAuthenticated: false,
                    forward: startLoginResponse.forward,
                });
            }
        }
    }
    // for unknown username, or loginshield not enabled,
    // return the same response to prevent user enumeration
    // for password-protected accounts
    req.session.userId = null;
    req.session.notAfter = null;
    return res.json({ isAuthenticated: false, error: 'password-required' });
}

// `realmScopedUserId` example: user.loginshield.userId
// `redirect` parameter example: `${ENDPOINT_URL}/account/loginshield/continue-registration`  (note the endpoint is enterprise own endpoint url, the path is defined by enterprise)
async function enableLoginShieldForAccount(req, res) {
    const { database } = req.app.locals;
    const { ENDPOINT_URL } = process.env;
    const isAuthenticated = isSessionAuthenticated(req.session);
    if (!isAuthenticated) {
        return res.json({ error: 'unauthorized' });
    }
    // check if we already have a loginshield userId
    const user = await database.collection('user').fetchById(req.session.userId);
    if (user && user.loginshield && user.loginshield.userId) {
        // user already has a loginshield userId
        return res.json({ forward: `${ENDPOINT_URL}/account/loginshield/continue-registration` });
    }
    console.log('enabling loginshield for account...');
    const loginshield = new RealmClient();
    const realmScopedUserId = randomHex(16); // three options: 1) service username (already unique), 2) hash of service username (need to check for conflict), 3) random (need to check for conflict)

    let response;
    if (process.env.REDIRECT_METHOD_ENABLED) {
        /* start redirect method */
        const redirect = `${ENDPOINT_URL}/account/loginshield/continue-registration`;
        response = await loginshield.createRealmUser({ realmScopedUserId, redirect });
        /* end redirect method */
    } else {
        /* immediate method (preferred) */
        console.log(`calling createRealmUser with name: ${user.username} and email ${user.email}`);
        response = await loginshield.createRealmUser({ realmScopedUserId, name: user.username, email: user.email });
    }
    if (response.isCreated) {
        // store the realm-scoped-user-id
        const loginWithLoginShield = {
            isEnabled: false,
            isRegistered: true, // true for immediate method; for the redirect method, set to false here and true later when redirected back to this site
            userId: realmScopedUserId, // not needed if we register user with realmScopedUserId = username
        };
        await database.collection('user').editById(req.session.userId, { loginshield: loginWithLoginShield });
        await database.collection('map_loginshielduserid_to_id').insert(realmScopedUserId, req.session.userId);
        /* start redirect method */
        if (response.forward) {
            // redirect user to loginshield to continue registration
            return res.json({ forward: response.forward });
        }
        /* end redirect method */
        /* immediate method, UI will proceed directly to first login at /account/loginshield/continue-registration (defined by UI) */
        return res.json({ isEdited: true });
    }
    return res.json({ error: 'unexpected reply from registration' });
}


async function httpPostEditAccount(req, res) {
    const { database } = req.app.locals;
    console.log('edit account request: %o', req.body);
    const isAuthenticated = isSessionAuthenticated(req.session);
    if (!isAuthenticated) {
        return res.json({ error: 'unauthorized' });
    }
    const user = await database.collection('user').fetchById(req.session.userId);
    console.log('user: %o', user);
    const { action } = req.body;
    if (action === 'register-loginshield-user') {
        return enableLoginShieldForAccount(req, res);
    }
    const { loginshield } = req.body;
    if (loginshield && user.loginshield && user.loginshield.isRegistered) {
        const copy = user.loginshield;
        copy.isEnabled = loginshield.isEnabled;
        const isEdited = await database.collection('user').editById(req.session.userId, { loginshield: copy });
        return res.json({ isEdited });
    }
    return res.json({ isEdited: false });
}

function installroutes(app) {
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
    routes.post('/session/login/password', httpPostLoginWithPassword);
    routes.post('/session/login/loginshield', httpPostLoginWithLoginShield);
    routes.post('/session/logout', httpPostLogout);
    // account management
    routes.get('/account', httpGetAccount);
    routes.post('/account/create', httpPostCreateAccount);
    routes.post('/account/edit', httpPostEditAccount);

    routes.use((err, req, res, next) => {
        if (err) {
            res.status(500);
            return res.json({ error: 'server-error' });
        }
        return next(err);
    });

    app.use('/', routes);
}

module.exports = { routes: installroutes };
