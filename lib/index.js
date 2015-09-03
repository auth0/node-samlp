exports.auth            = require('./samlp').auth;
exports.logout          = require('./samlp').logout;
exports.parseRequest    = require('./samlp').parseRequest;
exports.getSamlResponse = require('./samlp').getSamlResponse;
exports.sendError       = require('./samlp').sendError;
exports.metadata        = require('./metadata');
