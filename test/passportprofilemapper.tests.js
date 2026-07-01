var expect        = require('chai').expect;
var PassportProfileMapper = require('../lib/claims/PassportProfileMapper')

describe('PassportProfileMapper', function () {
    it('PassportProfileMapper.prototype.getNameIdentifier returns id', function() {
        var profileMapper = new PassportProfileMapper({
            'id': 'e9f7ac44-3f9c-488c-88a2-5b4b437749a9', 
            'emails': [],
            'displayName': null,
            'name': {
                'familyName': null,
                'givenName': null,
            }
        })
        var output = profileMapper.getNameIdentifier()
        expect(output.nameIdentifier).to.eql('e9f7ac44-3f9c-488c-88a2-5b4b437749a9')
    })

    it('PassportProfileMapper.prototype.getNameIdentifier returns name', function() {
        var profileMapper = new PassportProfileMapper({
            'id': null, 
            'emails': [],
            'displayName': 'Curious George',
            'name': {
                'familyName': null,
                'givenName': null,
            }
        })
        var output = profileMapper.getNameIdentifier()
        expect(output.nameIdentifier).to.eql('Curious George')
    })

    it('PassportProfileMapper.prototype.getNameIdentifier returns emails', function() {
        var profileMapper = new PassportProfileMapper({
            'id': null, 
            'emails': [{
                'value': 'george@example.com'
            }],
            'displayName': null,
            'name': {
                'familyName': null,
                'givenName': null,
            }
        })
        var output = profileMapper.getNameIdentifier()
        expect(output.nameIdentifier).to.eql('george@example.com')
    })

    it('PassportProfileMapper.prototype.getNameIdentifier returns undefined', function() {
        var profileMapper = new PassportProfileMapper({
            'id': null, 
            'emails': [],
            'displayName': null,
            'name': {
                'familyName': 'Curious George',
                'givenName': 'George',
            }
        })
        var output = profileMapper.getNameIdentifier()
        expect(output.nameIdentifier).to.eql(undefined)
    })
})