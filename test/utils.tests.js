const timekeeper = require('timekeeper');
const expect = require('chai').expect;

const utils = require('../lib/utils');

describe('utils', function () {
  describe('generateInstant', function () {
    it('should pad the millis appropriately', function () {
      timekeeper.withFreeze(0, () => {
        expect(utils.generateInstant()).to.equal('1970-01-01T00:00:00.000Z');
      });
    });
  });
});
