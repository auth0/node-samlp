var uid = require('uid2');

function SessionStore() {
  // we'll store everything inside this key in session
  this._key = 'logoutState';
  this._sp_initiated_key = 'sp_initiated';
  this._status_key = 'global_status';
}

SessionStore.prototype.storeSpInitiated = function(req, data, callback) {
  if (!req.session) { return callback(new Error('Single Logout requires session support when using state. Did you forget to use express-session middleware?')); }
  var key = this._key;

  if (!req.session[key]) { req.session[key] = {}; }
  
  // Initialize session
  if (!req.session[key][this._sp_initiated_key]) { req.session[key][this._sp_initiated_key] = {}; }

  data.relayState = req.query.RelayState || (req.body && req.body.RelayState);
  req.session[key][this._sp_initiated_key] = data;
  callback(null, data);
};

SessionStore.prototype.storeState = function(req, callback) {
  if (!req.session) { return callback(new Error('Single Logout requires session support when using state. Did you forget to use express-session middleware?')); }

  var key = this._key;
  var state = uid(24);
  // Initialize session  
  if (!req.session[key]) { req.session[key] = {}; }
  
  req.session[key].state = state;
  callback(null, state);
};

SessionStore.prototype.verifyState = function(req, providedState, callback) {
  if (!req.session) { return callback(new Error('Single Logout requires session support when using state. Did you forget to use express-session middleware?')); }

  var key = this._key;

  if (!req.session[key]) {
    return callback(null, false, { message: 'Unable to verify logout request state.' });
  }

  var state = req.session[key].state;
  if (!state) {
    return callback(null, false, { message: 'Unable to verify logout request state.' });
  }

  // we don't need it any more
  delete req.session[key].state;
  if(state !== providedState){
    return callback(null, false, { message: 'Unable to verify logout request state.' });
  }

  callback(null, true);
};

SessionStore.prototype.getSpInitiated = function(req, callback) {
  if (!req.session) { return callback(new Error('Single Logout requires session support when using state. Did you forget to use express-session middleware?')); }
  
  var key = this._key;
  if (!req.session[key]) { req.session[key] = {}; }
  
  callback(null, req.session[key][this._sp_initiated_key]);
};

SessionStore.prototype.setLogoutStatusFailed = function(req){
  if (!req.session[this._key]) { req.session[this._key] = {}; }

  req.session[this._key][this._status_key] = 'failed';
};

SessionStore.prototype.isLogoutFailed = function(req){
  if (!req.session[this._key]) { req.session[this._key] = {}; }

  return req.session[this._key][this._status_key] === 'failed';
};


// Expose constructor.
module.exports = SessionStore;