var ejs = require('ejs');
var fs = require('fs');
var path = require('path');

var templates = fs.readdirSync(path.join(__dirname, '../templates'));

templates.forEach(function (tmplFile) {
  var content = fs.readFileSync(path.join(__dirname, '../templates', tmplFile));
  var template = ejs.compile(content.toString());
  exports[tmplFile.slice(0, -4)] = template;
});