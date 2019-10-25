/*
Copyright (C) 2019 Cryptium Corporation. All rights reserved.
*/
/* eslint-disable no-console */


const nameRegex = new RegExp('[A-Z0-9]', 'i'); // simple rule: just has to include a letter or digit; TODO: allow all unicode letters
const emailRegex = new RegExp('^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$', 'i');
const phoneRegex = new RegExp('^[0-9#*()+,. -]+$', 'i');
const compactRegex = new RegExp('[^0-9a-zA-Z]', 'g'); // TODO: allow all unicode letters

function isValidName(v) {
    return (typeof v === 'string' && v.length > 0 && nameRegex.test(v));
}
function isValidEmail(v) {
    return (typeof v === 'string' && v.length > 0 && v.length < 255 && emailRegex.test(v));
}
function isValidPhone(v) {
    return (typeof v === 'string' && v.length > 0 && v.length < 64 && phoneRegex.test(v));
}

/**
 * Returns a version of the name consisting only of digits and
 * lowercase letters.
 */
function compact(name) {
    return name.toLowerCase().replace(compactRegex, '');
}

module.exports = {
    isValidName, isValidEmail, isValidPhone, compact,
};
