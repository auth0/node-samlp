var xmldom = require('@auth0/xmldom');
var DOMParser = xmldom.DOMParser;
var XMLSerializer = xmldom.XMLSerializer;
var whitespace = /^\s+$/;

function removeEmptyNodes(node) {
  for (var i = 0; i < node.childNodes.length; i++){
    var current = node.childNodes[i];
    if (current.nodeType === 3 && whitespace.test(current.nodeValue)) {
      node.removeChild(current);
    } else if (current.nodeType === 1) {
      removeEmptyNodes(current); //remove whitespace on child element's children
    }
  }
}

module.exports = function trimXML (xml) {
  var dom = new DOMParser().parseFromString(xml);
  var serializer = new XMLSerializer();
  removeEmptyNodes(dom);
  return serializer.serializeToString(dom);
};