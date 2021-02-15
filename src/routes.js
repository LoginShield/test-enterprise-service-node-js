const { WebauthzMemoryDatabase } = require('@webauthz/sdk-app-data-memory-js');
const { Webauthz } = require('@webauthz/sdk-app-core-node-js');
const { RealmClient } = require('@loginshield/realm-client-node');
const { Log } = require('@libertyio/log-node-js');
const { randomHex } = require('@cryptium/random-node-js');
const bodyParser = require('body-parser');
const cookie = require('cookie');
const crypto = require('crypto');
const { Router } = require('express');
const pkg = require('../package.json');

const COOKIE_NAME = 'test';

// webauthz plugin with in-memory database
const webauthzPlugin = new Webauthz({
    log: new Log({ tag: 'Webauthz', enable: { error: true, warn: true, info: true, trace: true } }),
    database: new WebauthzMemoryDatabase({ log: new Log({ tag: 'WebauthzMemoryDatabase', enable: { error: true, warn: true, info: true, trace: true } }), }),
    client_name: 'Enterprise Demo',
    grant_redirect_uri: `${process.env.ENDPOINT_URL}/webauthz/grant`,
    register_extra: {
        client_version: `LoginShield Demo v${pkg.version}`,
    },
});

function getRealmClient() {
    const { LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN } = process.env;

    // use pre-configured authorization token or webauthz access token
    let requestHeaders = null;
    if (LOGINSHIELD_AUTHORIZATION_TOKEN) {
        requestHeaders = async () => {
            return {
                Authorization: `Token ${LOGINSHIELD_AUTHORIZATION_TOKEN}`,
            };
        };
    } else {
        requestHeaders = async (url) => {
            const token = await webauthzPlugin.getAccessToken({ resource_uri: url, user_id: '#admin' });
            return {
                Authorization: `Token ${token}`,
            };
        };
    }

    let realmId = null;
    if (LOGINSHIELD_REALM_ID) {
        realmId = LOGINSHIELD_REALM_ID;
    }

    return new RealmClient({ realmId, requestHeaders });
}

// express middleware to ask browsers not to cache results
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

// this function is called by the UI to check if the LoginShield realm is configured or needs setup
// NOTE: in production, only authorized administrators should have access to this API
async function httpGetAdminLoginShield(req, res) {
    try {
        const { LOGINSHIELD_REALM_ID, LOGINSHIELD_ENDPOINT_URL, ENDPOINT_URL } = process.env;

        try {
            if (LOGINSHIELD_REALM_ID) {
                console.log('httpGetAdminLoginShield: trying with realm id');
                const loginshield = getRealmClient();
                const { id, icon } = await loginshield.getRealmInfoById(LOGINSHIELD_REALM_ID);
                console.log(`httpGetAdminLoginShield: result: id ${id}`);
                return res.json({ isEnabled: true, realmId: id, icon });
            } else {
                console.log('httpGetAdminLoginShield: trying with uri');
                const loginshield = getRealmClient();
                const { id, icon } = await loginshield.getRealmInfoByURI(ENDPOINT_URL);
                console.log(`httpGetAdminLoginShield: result: id ${id}`);
                console.log('httpGetAdminLoginShield: storing realm id');
                process.env.LOGINSHIELD_REALM_ID = id; // NOTE: in production this should be stored somewhere
                return res.json({ isEnabled: true, realmId: id, icon });
            }
        } catch (err) {
            console.log(`httpGetAdminLoginShield: error`, err);
            if (err.response) {
                const webauthzInfo = await webauthzPlugin.checkResponseForWebauthz({ user_id: '#admin', resource_uri: LOGINSHIELD_ENDPOINT_URL, http_response: err.response });
                console.log(`httpGetAdminLoginShield: webauthzInfo ${JSON.stringify(webauthzInfo)}`);
                if (webauthzInfo) {
                    // found a Webauthz challenge; prepare a Webauthz access request for the resource
                    const { access_request_uri } = await webauthzPlugin.createAccessRequest(webauthzInfo, { method: 'GET' });
                    // show the error we got from the resource, and also the fact that it supports Webauthz
                    return res.json({
                        isEnabled: false,
                        realmId: null,
                        error: `${err.response.status} ${err.response.statusText}`,
                        url: LOGINSHIELD_ENDPOINT_URL,
                        webauthz: access_request_uri,
                        // username: req.session.username
                    });
                }
            }
            return res.json({ error: 'unknown' });
        }
    } catch (err) {
        console.error('httpGetAdminLoginShield failed', err);
        return res.json({ error: 'unknown' });
    }
}

// this function is called by the UI when the administrator returns from LoginShield after requesting access
// NOTE: in production, only authorized administrators should have access to this API
async function httpPostAdminLoginShieldWebauthzGrant(req, res) {
    const { client_id, client_state, status, grant_token } = req.body;

    console.log(`httpPostAdminLoginShieldWebauthzGrant client_id ${client_id} client_state ${client_state} status ${status} grant_token ${grant_token}`);

    if (typeof client_id !== 'string' || !client_id) {
        res.status(400);
        return res.json({ error: 'client_id required' });
    }
    if (typeof client_state !== 'string' || !client_state) {
        res.status(400);
        return res.json({ error: 'client_state required' });
    }

    try {
        if (status === 'denied') {
            console.log(`httpPostAdminLoginShieldWebauthzGrant access request denied`);
            const isDeleted = await webauthzPlugin.deleteAccessRequest(client_state, '#admin');
            if (isDeleted) {
                return res.json({ status: 'deleted' });
            } else {
                return res.json({ error: 'failed to delete access request' });
            }
        }

        if (typeof grant_token === 'string') {
            console.log(`httpPostAdminLoginShieldWebauthzGrant access request granted`);

            try {
                // exchange the grant token for an access token
                const { status: exchange_status } = await webauthzPlugin.exchange({ client_id, client_state, grant_token, user_id: '#admin' });
                if (exchange_status === 'granted') {
                    return res.json({ status: 'ok' });
                }
            } catch (err) {
                console.error('httpGetWebauthzGrant: error', err);
                res.status(403);
                return res.json({ error: 'failed to process access request' });
            }

            return res.json({ status: 'finished' });
        }

        res.status(400);
        return res.json({ error: 'bad request' });
    } catch (err) {
        console.error('httpGetWebauthzGrant: failed to retrieve access request', err);
        res.status(400);
        return res.json({ error: 'failed to retrieve access request' });
    }
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
            const { username, email, loginshield: { isRegistered, isConfirmed, isEnabled } } = account;
            return res.json({ username, email, loginshield: { isRegistered, isConfirmed, isEnabled } });
        }
    }
    return res.json({ error: 'unauthorized' });
}

async function httpPostCreateAccount(req, res) {
    const { database } = req.app.locals;
    console.log('httpPostCreateAccount request: %o', req.body);
    const { username, email, password } = req.body;
    // validate inputs
    if (typeof username !== 'string' || username.trim().length === 0) {
        console.log('httpPostCreateAccount: non-empty username is required');
        return res.json({ isCreated: false, error: 'username-required' });
    }
    if (typeof email !== 'string' || email.trim().length === 0) {
        console.log('httpPostCreateAccount: non-empty email is required');
        return res.json({ isCreated: false, error: 'email-required' });
    }
    if (typeof password !== 'string' || password.trim().length === 0) {
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
        loginshield: { isRegistered: false, isConfirmed: false, isEnabled: false },
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
        const loginshield = getRealmClient();
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
                            isConfirmed: true,
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
                const loginshield = getRealmClient();
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
                const loginshield = getRealmClient();
                const startLoginResponse = await loginshield.startLogin({ realmScopedUserId: user.loginshield.userId, isNewKey: true, redirect: `${ENDPOINT_URL}/login?mode=resume-loginshield` });
                console.log('got startLoginResponse: %o', JSON.stringify(startLoginResponse));
                return res.json({
                    isAuthenticated: true,
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
    const loginshield = getRealmClient();
    const realmScopedUserId = randomHex(16); // three options: 1) service username (already unique), 2) hash of service username (need to check for conflict), 3) random (need to check for conflict)

    let response;
    if (process.env.REDIRECT_METHOD_ENABLED) {
        /* start redirect method */
        const redirect = `${ENDPOINT_URL}/account/loginshield/continue-registration`;
        response = await loginshield.createRealmUser({ realmScopedUserId, redirect });
        /* end redirect method */
    } else {
        /* immediate method (preferred); replace the account if it's already created because this is a demo */
        console.log(`calling createRealmUser with name: ${user.username} and email ${user.email}`);
        try {
            response = await loginshield.createRealmUser({ realmScopedUserId, name: user.username, email: user.email, replace: true });
            console.log(`response from loginshield: ${JSON.stringify(response)}`);
            if (response.error) {
                console.error('failed to register new user', response.error);
                return res.json({ isEdited: false, error: 'registration failed' });
            }
        } catch (err) {
            console.error('failed to register new user', err);
            return res.json({ isEdited: false, error: 'registration failed' });
        }
    }
    if (response.isCreated) {
        // store the realm-scoped-user-id
        const loginWithLoginShield = {
            isEnabled: false,
            isRegistered: true, // true for immediate method; for the redirect method, set to false here and true later when redirected back to this site
            isConfirmed: false,
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
    if (loginshield && user.loginshield && user.loginshield.isRegistered && user.loginshield.isConfirmed) {
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
    routes.get('/admin/loginshield', httpGetAdminLoginShield);
    routes.post('/admin/loginshield-webauthz-grant', httpPostAdminLoginShieldWebauthzGrant);
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

    app.use('/service', routes);
}

module.exports = { routes: installroutes };
