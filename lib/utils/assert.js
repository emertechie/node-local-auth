'use strict';

const assert = require('assert');

module.exports = function(val, msg) {
    assert(val, msg);
    return val;
};