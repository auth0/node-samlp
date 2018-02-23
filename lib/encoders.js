var thumbprint = require('@auth0/thumbprint');

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