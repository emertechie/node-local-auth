'use strict';

var _ = require('lodash');

class FakeTokenStore {
    constructor() {
        this.tokens = [];
        this.lastId = 0;
    }
    add(tokenObj) {
        var cloned = _.cloneDeep(tokenObj);
        cloned.tokenId = 'Token#' + (++this.lastId);
        this.tokens.push(cloned);
        return Promise.resolve();
    }
    removeAllByEmail(email) {
        _.remove(this.tokens, function(token) {
            return token.email === email;
        });
        return Promise.resolve();
    }
    findByEmail(email) {
        var found = _.find(this.tokens, function(token) {
            return token.email === email;
        });
        return Promise.resolve(found);
    }
}

module.exports = FakeTokenStore;