'use strict';

const ValidationError = require('../errors/validationError');

module.exports = {
    assertValid: function(result, message) {
        let errMsg;
        if (result.error) {
            errMsg = message || result.error.details[0].message;
        } else if (result.valid === false) {
            errMsg = message || result.message;
        }
        if (errMsg) {
            throw new ValidationError(errMsg);
        }
        return result.value;
    }
};