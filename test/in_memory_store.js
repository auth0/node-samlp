var uid = require('uid2');

function Store() {
  this.clear();
}

Store.prototype.save = function(req, data, cb) {
  var key = uid(8);
  return this.update(req, key, data, cb);
};

Store.prototype.update = function(req, key, data, cb) {
  this._memoryStore[key] = data;
  if (cb) { cb(null, key); }
};

Store.prototype.load = function(req, key, options, cb) {
  if (typeof options === 'function') {
    cb = options;
    options = {};
  }

  var result = this._memoryStore[key];
  if (options.destroy) {
    delete this._memoryStore[key];
  }

  cb(null, result);
};

Store.prototype.clear = function(cb) {
  this._memoryStore = {};
  if (cb) { cb(); }
};


module.exports = Store;