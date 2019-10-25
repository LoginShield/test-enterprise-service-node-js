var expect  = require('chai').expect;
const { randomHex, randomBase32, randomBase64 } = require('../../src/random');

describe('random', function(){
    describe('randomHex', function(){
        it('initialRandomHex', function(){
            const result = randomHex(1);
            expect(result.length).to.equal(2);
        })
        it('emptyRandomHex', function() {
            const result = randomHex(0);
            expect(result).to.equal('');
        })
    })
    describe('randomBase64', function(){
        it('initialRandomBase64', function(){
            const result = randomBase64(3);
            expect(result.length).to.equal(4);
        })
        it('emptyRandomBase64', function() {
            const result = randomBase64(0);
            expect(result).to.equal('');
        })
    })
})
