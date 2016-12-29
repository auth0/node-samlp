function Store() {
}

Store.prototype.storeSpInitiated = function(req, data, cb) {
  data.relayState = req.query.RelayState || (req.body && req.body.RelayState);
  this.request = data;
  if (cb) { cb(); }
};

Store.prototype.getSpInitiated = function(req, cb) {
  cb(null, this.request);
};

Store.prototype.clear = function(cb) {
  this.request = null;
  if (cb) { cb(); }
};

Store.prototype.setLogoutStatusFailed = function(){
  this.failed = true;
};

Store.prototype.isLogoutFailed = function(){
  return this.failed;
};

Store.prototype.storeState = function(req, callback) {
  callback(null, req.query.RelayState || (req.body && req.body.RelayState));
};

Store.prototype.verifyState = function(req, providedState, callback) {
  callback(null, true);
};


module.exports = Store;