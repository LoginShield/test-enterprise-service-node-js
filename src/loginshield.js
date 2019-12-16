const ajax = require('axios');

// TODO: move to enterprise service SDK
function loginshieldConfiguration() {
    let isConfError = false;
    ['LOGINSHIELD_ENDPOINT_URL', 'LOGINSHIELD_REALM_ID', 'LOGINSHIELD_AUTHORIZATION_TOKEN'].forEach((item) => {
        if (!process.env[item]) {
            console.error(`environment variable is required: ${item}`);
            isConfError = true;
        }
    });
    if (isConfError) {
        throw new Error('configuration-not-found');
    }
    const {
        LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
    } = process.env;
    return {
        LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
    };
}
// TODO: move to enterprise service SDK
async function loginshieldCreateUser({ redirect }) {
    try {
        const {
            LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
        } = loginshieldConfiguration();
        const request = {
            realmId: LOGINSHIELD_REALM_ID,
            redirect, // where loginshield will redirect the user after the user authenticates and confirms the link with the realm (the enterprise should complete the registration with the first login with loginshield at this url)
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

// TODO: move to enterprise service SDK
// NOTE: this is second draft of the enterprise login where we get a url and redirect user
async function loginshieldStartLogin({ realmScopedUserId, redirect, isNewKey = false }) {
    try {
        const {
            LOGINSHIELD_ENDPOINT_URL, LOGINSHIELD_REALM_ID, LOGINSHIELD_AUTHORIZATION_TOKEN,
        } = loginshieldConfiguration();
        const request = {
            realmId: LOGINSHIELD_REALM_ID,
            userId: realmScopedUserId,
            isNewKey,
            redirect, // this url only used for safety reset; when called, a 'loginshield' parameter will be added by loginshield
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

module.exports = { loginshieldCreateUser, loginshieldStartLogin, loginshieldFinishLogin };
