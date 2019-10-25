const crypto = require('crypto');

function randomBuffer(lengthBytes) {
  const buffer = Buffer.alloc(lengthBytes);
  crypto.randomFillSync(buffer);
  return buffer;
}

function randomHex(lengthBytes) {
  return randomBuffer(lengthBytes).toString('hex');
}
function randomBase64(lengthBytes) {
  return randomBuffer(lengthBytes).toString('base64');
}

module.exports = { randomHex, randomBase64 };
