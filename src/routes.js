const { randomHex } = require('@cryptiumtech/random-util');
// const { strict: assert } = require('assert');
const ajax = require('axios');
const bodyParser = require('body-parser');
const cookie = require('cookie');
const crypto = require('crypto');
const { Router /* , json */ } = require('express');
// const fs = require('fs');
// const { compact } = require('./input');
const pkg = require('../package.json');

const COOKIE_NAME = 'test';


// TODO: move to enterprise service SDK
function loginshieldConfiguration() {
    let isConfError = false;
    ['ENDPOINT_URL', 'LOGINSHIELD_ENDPOINT_URL', 'LOGINSHIELD_REALM_ID', 'LOGINSHIELD_AUTHORIZATION_TOKEN'].forEach((item) => {
        if (!process.env[item]) {
            console.error(`environment variable is required: ${item}`);
            isConfError = true;
        }
    });
    if (isConfError) {
        throw new Error('configuration-not-found');
    }
    const {
        ENDPOINT_URL, LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
    } = process.env;
    return {
        ENDPOINT_URL, LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
    };
}
// TODO: move to enterprise service SDK
async function loginshieldCreateUser() {
    try {
        const {
            ENDPOINT_URL, LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
        } = loginshieldConfiguration();
        const request = {
            realmId: LOGINSHIELD_REALM_ID,
            redirect: `${ENDPOINT_URL}/account/loginshield/continue-registration`,
        };
        console.log('registration request: %o', request);
        const headers = {
            Authorization: `Token ${LOGINSHIELD_AUTHORIZATION_TOKEN}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
        };
        const response = await ajax.post(
            `${LOGINSHIELD_ENDPOINT_URL}/service/realm/user/create`,
            JSON.stringify(request),
            {
                headers,
            },
        );
        console.log('loginshield response status: %o', response.status);
        console.log('loginshield response status text: %o', response.statusText);
        console.log('loginshield response headers: %o', response.headers);
        console.log('loginshield response data: %o', response.data);
        if (response.data && response.data.userId && response.data.forward && response.data.forward.startsWith(LOGINSHIELD_ENDPOINT_URL)) {
            return response.data; // { userId, forward }
        }
        return { error: 'unexpected-response', response };
    } catch (err) {
        console.log('registration error', err);
        return { error: 'registration-failed', err };
    }
}

/*
// TODO: move to enterprise service SDK
// NOTE: this is first draft of the enterprise login where we get the challenge and give it to client
async function loginshieldCreateLoginChallenge(realmScopedUserId) {
    try {
        const {
            ENDPOINT_URL, LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
        } = loginshieldConfiguration();
        const request = {
            realmId: LOGINSHIELD_REALM_ID,
            userId: realmScopedUserId,
            redirect: `${ENDPOINT_URL}/account/loginshield/continue-login`,
        };
        console.log('login challenge request: %o', request);
        const headers = {
            Authorization: `Token ${LOGINSHIELD_AUTHORIZATION_TOKEN}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
        };
        const response = await ajax.post(
            `${LOGINSHIELD_ENDPOINT_URL}/service/realm/login/challenge`,
            JSON.stringify(request),
            {
                headers,
            },
        );
        console.log('loginshield response status: %o', response.status);
        console.log('loginshield response status text: %o', response.statusText);
        console.log('loginshield response headers: %o', response.headers);
        console.log('loginshield response data: %o', response.data);
        if (response.data && response.data.challenge) {
            return response.data; // { challenge (base64 string) }
        }
        return { error: 'unexpected-response', response };
    } catch (err) {
        console.log('login challenge error', err);
        return { error: 'login-failed', err };
    }
}
*/

// TODO: move to enterprise service SDK
// NOTE: this is second draft of the enterprise login where we get a url and redirect user
async function loginshieldStartLogin({ realmScopedUserId, isNewKey = false }) {
    try {
        const {
            ENDPOINT_URL, LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
        } = loginshieldConfiguration();
        const request = {
            realmId: LOGINSHIELD_REALM_ID,
            userId: realmScopedUserId,
            isNewKey,
            redirect: `${ENDPOINT_URL}/login?mode=resume-loginshield`, // draft 2, this url only used for safety reset; when called, a 'loginshield' parameter will be added by loginshield
        };
        console.log('login start request: %o', request);
        const headers = {
            Authorization: `Token ${LOGINSHIELD_AUTHORIZATION_TOKEN}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
        };
        const response = await ajax.post(
            `${LOGINSHIELD_ENDPOINT_URL}/service/realm/login/start`,
            JSON.stringify(request),
            {
                headers,
            },
        );
        console.log('loginshield response status: %o', response.status);
        console.log('loginshield response status text: %o', response.statusText);
        console.log('loginshield response headers: %o', response.headers);
        console.log('loginshield response data: %o', response.data);
        if (response.data && response.data.forward && response.data.forward.startsWith(LOGINSHIELD_ENDPOINT_URL)) {
            return response.data; // { forward (url string) }
        }
        return { error: 'unexpected-response', response };
    } catch (err) {
        console.log('login start error', err);
        return { error: 'login-failed', err };
    }
}

// TODO: move to enterprise service SDK
// NOTE: this is second draft of the enterprise login where we get a url and redirect user, later (here) we get a token, validate it with loginshield service, and login the user
async function loginshieldFinishLogin(token) {
    try {
        const {
            LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_AUTHORIZATION_TOKEN,
        } = loginshieldConfiguration();
        const request = {
            token,
        };
        console.log('login finish request: %o', request);
        const headers = {
            Authorization: `Token ${LOGINSHIELD_AUTHORIZATION_TOKEN}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
        };
        const response = await ajax.post(
            `${LOGINSHIELD_ENDPOINT_URL}/service/realm/login/report`,
            JSON.stringify(request),
            {
                headers,
            },
        );
        console.log('loginshield login report response status: %o', response.status);
        console.log('loginshield login report response status text: %o', response.statusText);
        console.log('loginshield login report response headers: %o', response.headers);
        console.log('loginshield login report response data: %o', response.data);
        if (response.data) {
            return response.data;
        }
        return { error: 'unexpected-response', response };
    } catch (err) {
        const { config, response } = err;
        if (config) { // this is also in response.config
            const {
                url, method, data, headers,
            } = config;
            const headersJson = JSON.stringify(headers);
            const dataJSON = JSON.stringify(data);
            console.log(`login finish error: request method ${method} url ${url} data ${dataJSON} headers ${headersJson}`);
        }
        if (response) {
            const {
                status, statusText, headers, data,
            } = response;
            const headersJson = JSON.stringify(headers);
            const dataJSON = JSON.stringify(data);
            console.log(`login finish error: response ${status} ${statusText} data ${dataJSON} headers ${headersJson}`);
        }
        console.log('login finish error', err);
        return { error: 'login-failed' };
    }
}


function setNoCache(req, res, next) {
    res.set('Pragma', 'no-cache');
    res.set('Cache-Control', 'no-cache, no-store');
    next();
}

async function session(req, res, next) {
    const { database } = req.app.locals;
    let sessionId;
    let sessionInfo;
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
        sessionInfo = {};
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

async function httpGetVersion(req, res) {
    return res.json({ name: pkg.name, version: pkg.version });
}
async function httpGetContext(req, res) {
    return res.json({});
}

async function httpGetSession(req, res) {
    const { isAuthenticated, userId } = req.session;
    if (isAuthenticated && userId) {
        return res.json({ isAuthenticated: true });
    }
    return res.json({ isAuthenticated: false });
}

async function httpPostLogout(req, res) {
    req.session.isAuthenticated = false;
    req.session.userId = null;
    return res.json({ isAuthenticated: false });
}

async function httpGetAccount(req, res) {
    const { database } = req.app.locals;
    if (req.session.isAuthenticated && req.session.userId) {
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
    console.log('register request: %o', req.body);
    const { username, email, password } = req.body;
    // check if user already exists
    const result = await database.collection('map_username_to_id').fetchById(username);
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
        username,
        email,
        password: { salt, hash },
        loginshield: { isRegistered: false, isEnabled: false },
    });
    await database.collection('map_username_to_id').insert(username, { id: userId });
    req.session.isAuthenticated = true;
    req.session.userId = userId;
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
    req.session.isAuthenticated = false;
    req.session.userId = null;
    const { database } = req.app.locals;
    console.log('login request: %o', req.body);
    const { username } = req.body;
    if (!username) {
        return res.json({ error: 'username-required' });
    }
    const result = await database.collection('map_username_to_id').fetchById(username);
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
    req.session.isAuthenticated = false;
    req.session.userId = null;
    const { database } = req.app.locals;
    console.log('httpPostLoginWithPassword request: %o', req.body);
    const { username, password } = req.body;
    if (!username) {
        return res.json({ isAuthenticated: false, error: 'username-required' });
    }
    if (!password) {
        return res.json({ isAuthenticated: false, error: 'password-required' });
    }
    const result = await database.collection('map_username_to_id').fetchById(username);
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
                req.session.isAuthenticated = true;
                req.session.userId = userId;
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
    console.log('httpPostLoginWithLoginShield request: %o', req.body);
    const { username, mode, verifyToken } = req.body;
    // to initiate a login, parameters are username (required), mode (optional)
    // to complete a login, parameters are token (required)
    if (verifyToken) {
        const finishLoginResponse = await loginshieldFinishLogin(verifyToken);
        if (finishLoginResponse.error || finishLoginResponse.fault) {
            return { isAuthenticated: false };
        }
        // TODO: the report includes the authorization certificate, we could parse it, extract the challenge, check the realm id in the challenge equals our realm id and equals the realm id mentioned in the report, check the realm scoped user id in the challenge is equal to realm scoped user id mentioned in the report, check that the public key that verifies the authorization certificate matches the public key stored for the user, check dates, nonce, etc.; these are all things that loginshield already verifies and provides the proof so the verification can be repeated here immediately or later in an audit
        // TODO: we could check that the session that started the login for the realmscopeduserid is the same one that
        // started the login, to prevent anyone from stealing a token for a process they didn't start; loginshield already
        // verifies its the same client, but we could also do the same check
        const {
            LOGINSHIELD_REALM_ID,
        } = loginshieldConfiguration();
        if (finishLoginResponse.realmId === LOGINSHIELD_REALM_ID) {
        // we need to lookup the username by realmScopedUserId OR we need to know the original token we sent with the user, so we can lookup the username there, because that's how the whole thing started anyway
            const result = await database.collection('map_loginshielduserid_to_id').fetchById(finishLoginResponse.realmScopedUserId);
            if (result && result.id) {
                const userId = result.id;
                const user = await database.collection('user').fetchById(userId);
                if (user) {
                    if (user.loginshield && !user.loginshield.isEnabled) {
                        const loginshield = {
                            isEnabled: true,
                            isRegistered: true,
                            userId: finishLoginResponse.realmScopedUserId,
                        };
                        await database.collection('user').editById(userId, { loginshield });
                    }
                    req.session.isAuthenticated = true;
                    req.session.userId = userId;
                    return res.json({ isAuthenticated: true });
                }
            }
        }
        // token provided but not validated
        return res.json({ isAuthenticated: false });
    }
    if (!username) {
        return res.json({ isAuthenticated: false, error: 'username-required' });
    }
    const result = await database.collection('map_username_to_id').fetchById(username);
    if (result && result.id) {
        const userId = result.id;
        const user = await database.collection('user').fetchById(userId);
        if (user) {
            // respond with required authentication method
            if (user.loginshield.isEnabled && user.loginshield.userId) {
                const startLoginResponse = await loginshieldStartLogin({ realmScopedUserId: user.loginshield.userId });
                console.log('got startLoginResponse: %o', JSON.stringify(startLoginResponse));
                return res.json({
                    isAuthenticated: false,
                    forward: startLoginResponse.forward,
                });
            }
            if (req.session.isAuthenticated && mode === 'activate-loginshield') {
                // user must already be registered with loginshield and have a realm-scoped-user-id
                if (!user.loginshield.userId) {
                    console.log('loginshield registration required before login');
                    return res.json({ isAuthenticated: false, error: 'registration-required' });
                }
                // we indicate in the start login request that this login is for completing
                // the realm user registration process
                const startLoginResponse = await loginshieldStartLogin({ realmScopedUserId: user.loginshield.userId, isNewKey: true });
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
    req.session.isAuthenticated = false;
    req.session.userId = null;
    return res.json({ isAuthenticated: false, error: 'password-required' });
}

async function enableLoginShieldForAccount(req, res) {
    const { database } = req.app.locals;
    if (!req.session.isAuthenticated || !req.session.userId) {
        return res.json({ error: 'unauthorized' });
    }
    // check if we already have a loginshield userId
    const user = await database.collection('user').fetchById(req.session.userId);
    if (user && user.loginshield && user.loginshield.userId) {
        // user already has a loginshield userId
        const {
            ENDPOINT_URL,
        } = loginshieldConfiguration();
        return res.json({ forward: `${ENDPOINT_URL}/account/loginshield/continue-registration` });
    }
    console.log('enabling loginshield for account...');
    const response = await loginshieldCreateUser();
    if (response.userId && response.forward) {
        // store the realm-scoped-user-id
        const loginshield = {
            isEnabled: false,
            isRegistered: false,
            userId: response.userId,
        };
        await database.collection('user').editById(req.session.userId, { loginshield });
        await database.collection('map_loginshielduserid_to_id').insert(response.userId, { id: req.session.userId });
        // redirect user to loginshield to continue registration
        return res.json({ forward: response.forward });
    }
    return res.json({ error: 'unexpected reply from registration' });
}


async function httpPostEditAccount(req, res) {
    const { database } = req.app.locals;
    console.log('edit account request: %o', req.body);
    if (!req.session.isAuthenticated || !req.session.userId) {
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
