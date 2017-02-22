exports.auth            = require('./samlp').auth;
exports.logout          = require('./logout').logout;
exports.sendLogoutError = require('./logout').sendLogoutError;
exports.parseRequest    = require('./samlp').parseRequest;
exports.getSamlResponse = require('./samlp').getSamlResponse;
exports.sendError       = require('./samlp').sendError;
exports.metadata        = require('./metadata');
