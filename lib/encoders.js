var thumbprint = require('thumbprint');

var removeHeaders = module.exports.removeHeaders = function  (cert) {
  var pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return null;
};

module.exports.thumbprint = function (pem) {
  var cert = removeHeaders(pem);
  return thumbprint.calculate(cert).toUpperCase();
};

module.exports.toCertifiedStore = function (pem) {
  var cert = removeHeaders(pem);
  var certBuffer = new Buffer(cert, 'base64');

  var header = new Buffer(8);
  header.writeUInt32LE(0x00000000, 0);
  header.writeUInt32LE(0x54524543, 4);


  var start = new Buffer(12);
  start.writeUInt32LE(0x00000020, 0);
  start.writeUInt32LE(0x00000001, 4);
  start.writeUInt32LE(certBuffer.length, 8);

  var ending = new Buffer(12);
  ending.writeUInt32LE(0x00000000, 0);
  ending.writeUInt32LE(0x00000000, 4);

  return Buffer.concat([header, start, certBuffer, ending]).toString('base64');
};