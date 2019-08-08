var templates             = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var encoders              = require('./encoders');

var URL_PATH              = '/FederationMetadata/2007-06/FederationMetadata.xml';

function getEndpointAddress (req, endpointPath) {
  endpointPath = endpointPath ||
    (req.originalUrl.substr(0, req.originalUrl.length - URL_PATH.length));

  var protocol = req.headers['x-iisnode-https'] && req.headers['x-iisnode-https'] == 'on' ?
                 'https' :
                 (req.headers['x-forwarded-proto'] || req.protocol);
  var host = req.headers['x-forwarded-host'] || req.headers['host'];
  return protocol + '://' + host + endpointPath;
}

/**
 * SAML metadata endpoint
 *
 * This endpoint returns a SAML metadata document.
 *
 * You should expose this endpoint in an address like:
 *
 * 'https://your-saml-server.com/FederationMetadata/2007-06/FederationMetadata.xml
 *
 * options:
 * - issuer string
 * - cert the public certificate
 * - profileMapper a function that given a user returns a claim based identity, also contains the metadata. By default maps from Passport.js user schema (PassportProfile).
 * - redirectEndpointPath optional, location value for HTTP-Redirect binding (SingleSignOnService)
 * - postEndpointPath optional, location value for HTTP-POST binding (SingleSignOnService)
 * - logoutEndpointPaths.redirect optional, location value for HTTP-Redirect binding (SingleLogoutService)
 * - logoutEndpointPaths.post optional, location value for HTTP-POST binding (SingleLogoutService)
 *
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
 */
function metadataMiddleware (options) {
  options = options || {};

  if(!options.issuer) {
    throw new Error('options.issuer is required');
  }

  if(!options.cert) {
    throw new Error('options.cert is required');
  }

  var claimTypes = (options.profileMapper || PassportProfileMapper).prototype.metadata;
  var issuer = options.issuer;
  var pem = encoders.removeHeaders(options.cert);

  return function (req, res) {
    var redirectEndpoint = getEndpointAddress(req, options.redirectEndpointPath);
    var postEndpoint = getEndpointAddress(req, options.postEndpointPath);

    options.logoutEndpointPaths = options.logoutEndpointPaths || { redirect: '/logout' };

    var logoutEndpoints = {};
    ['redirect', 'post'].forEach(function (binding) {
      if (options.logoutEndpointPaths[binding]) {
        logoutEndpoints[binding] = getEndpointAddress(req, options.logoutEndpointPaths[binding]);
      }
    });

    res.set('Content-Type', 'application/xml');

    res.send(templates.metadata({
      claimTypes: claimTypes,
      pem:              pem,
      issuer:           issuer,
      redirectEndpoint: redirectEndpoint,
      postEndpoint:     postEndpoint,
      logoutEndpoints:  logoutEndpoints
    }).replace(/\n(?:\s*\n)+/g, '\n'));
  };
}

module.exports = metadataMiddleware;
