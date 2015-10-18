'use strict';

const DuplicateRegistrationError = require('../../lib/errors/duplicateRegistrationError');
const _ = require('lodash');

class FakeUserStore {
    constructor() {
        this.users = [];
    }
    add(userData) {
        const userAlreadyExists = !!_findByEmail.call(this, userData.email);
        if (userAlreadyExists) {
            return Promise.reject(new DuplicateRegistrationError('A user with that email address already exists'));
        }
        let user = _.cloneDeep(userData);
        user.id = 'User#' + (this.users.length + 1);
        this.users.push(user);
        return Promise.resolve(user);
    }
    getByEmail(email) {
        const found = _findByEmail.call(this, email);
        return Promise.resolve(_.cloneDeep(found));
    }
    setEmailVerified(email) {
        var userIdx = _.findIndex(this.users, candidateUser => {
            return candidateUser.email === email;
        });
        if (userIdx === -1) {
            return Promise.reject(new Error('User not found'));
        }
        this.users[userIdx].emailVerified = true;
        return Promise.resolve();
    }
    setHashedPassword(user, hashedPassword) {
        var userIdx = _.findIndex(this.users, candidateUser => {
            return candidateUser.email === user.email;
        });
        if (userIdx === -1) {
            return Promise.reject(new Error('User not found'));
        }
        this.users[userIdx].hashedPassword = hashedPassword;
        return Promise.resolve();
    }
    removeByEmail(email) {
        _.remove(this.users, function(user) {
            return user.email === email;
        });
        return Promise.resolve();
    }
}

function _findByEmail(email) {
    return _.find(this.users, function(user) {
        return user.email === email;
    });
}

function _findById(id) {
    return _.find(this.users, function(user) {
        return user.id === id;
    });
}

module.exports = FakeUserStore;
