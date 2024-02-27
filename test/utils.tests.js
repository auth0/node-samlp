const timekeeper = require("timekeeper");
const DOMParser = require("@auth0/xmldom").DOMParser;
const expect = require("chai").expect;

const utils = require("../lib/utils");

const signedResponse = require("./fixture/signed_response");

describe("utils", function () {
  describe("generateInstant", function () {
    it("should pad the millis appropriately", function () {
      timekeeper.withFreeze(0, () => {
        expect(utils.generateInstant()).to.equal("1970-01-01T00:00:00.000Z");
      });
    });
  });
  describe("generateUniqueID", function () {
    it("should generate an ID 20 chars long", function () {
      expect(utils.generateUniqueID().length).to.equal(20);
    });
  });
  describe("generateUniqueID", function () {
    it("should generate an ID from the alphabet", function () {
      expect("abcdef0123456789".split("")).to.include.members(
        utils.generateUniqueID().split("")
      );
    });
  });
  describe("validateSignature", function () {
    describe("with custom signing certificate", function () {
      it("should validate the signature correctly", function () {
        const response = signedResponse.response;

        const req = { body: { SAMLResponse: response }, query: {} };
        const element_type = "LOGOUT_RESPONSE";
        const xml = new DOMParser().parseFromString(signedResponse.xml);
        const options = { signingCert: signedResponse.cert, deflate: true };

        // should not throw errors
        expect(utils.validateSignature(req, element_type, xml, options)).to.be
          .undefined;
      });
    });
  });
});
