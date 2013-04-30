var templates = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var URL_PATH = '/FederationMetadata/2007-06/FederationMetadata.xml';
var encoders = require('./encoders');

function getEndpointAddress (req, endpointPath) {
  endpointPath = endpointPath || 
    (req.originalUrl.substr(0, req.originalUrl.length - URL_PATH.length));

  var protocol = req.headers['x-iisnode-https'] && req.headers['x-iisnode-https'] == 'on' ? 
                 'https' : 
                 (req.headers['x-forwarded-proto'] || req.protocol);
  
  return protocol + '://' + req.headers['host'] + endpointPath;
}

/**
 * WSFederation metadata endpoint
 *
 * This endpoint returns a wsfederation metadata document.
 * 
 * You should expose this endpoint in an address like:
 *
 * 'https://your-wsfederation-server.com/FederationMetadata/2007-06/FederationMetadata.xml
 * 
 * options:
 * - issuer string
 * - cert the public certificate
 * - profileMapper a function that given a user returns a claim based identity, also contains the metadata. By default maps from Passport.js user schema (PassportProfile).
 * - endpointPath optional, defaults to the root of the fed metadata document.
 * 
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
 */
function metadataMiddleware (options) {
  //claimTypes, issuer, pem, endpointPath
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
    var endpoint = getEndpointAddress(req, options.endpointPath);

    res.set('Content-Type', 'application/xml');

    res.send(templates.metadata({
      claimTypes: claimTypes,
      pem:        pem,
      issuer:     issuer,
      endpoint:   endpoint
    }).replace(/\n/g, ''));
  };
}

module.exports = metadataMiddleware;