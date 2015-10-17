'use strict';

const chai = require('chai');
const assert = chai.assert;

module.exports = {
    assertThrows: function *(generatorFn) {
        let err;
        try {
            yield generatorFn();
        } catch (e) {
            err = e;
        }
        assert.ok(err, 'Throws exception');
        return err;
    }
};