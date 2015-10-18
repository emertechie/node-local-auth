'use strict';

const DuplicateRegistrationError = require('../../lib/errors/duplicateRegistrationError');
const _ = require('lodash');

class FakeUserStore {
    constructor() {
        this.users = [];
    }
    static get userIdGetter() {
        return user => user.id;
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
    getById(userId) {
        const found = _findById.call(this, userId);
        return Promise.resolve(_.cloneDeep(found));
    }
    getByEmail(email) {
        const found = _findByEmail.call(this, email);
        return Promise.resolve(_.cloneDeep(found));
    }
    update(user) {
        var userIdx = _.findIndex(this.users, candidateUser => {
            return FakeUserStore.userIdGetter(candidateUser) === FakeUserStore.userIdGetter(user);
        });

        if (userIdx === -1) {
            return Promise.reject(new Error('User not found'));
        }

        var updated = _.cloneDeep(user);
        this.users[userIdx] = updated;
        return Promise.resolve(updated);
    }
    removeById(userId) {
        _.remove(this.users, function(user) {
            return user.id === userId;
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




/*
var _ = require('lodash');

function FakeUserStore() {
    this.users = [];
}

FakeUserStore.prototype.add = function(userDetails, callback) {
    var userAlreadyExists = !!_findByEmail.call(this, userDetails.email);
    if (userAlreadyExists) {
        return callback(null, userAlreadyExists);
    }

    var user = _.clone(userDetails);
    user.id = this.fakeUserId || ('User#' + (this.users.length + 1));
    this.users.push(user);
    callback(null, userAlreadyExists, user);
};

FakeUserStore.prototype.get = function(userId, cb) {
    var user = _.find(this.users, function(user) {
        return user.id === userId;
    });
    cb(null, user);
};

FakeUserStore.prototype.update = function(user, callback) {
    var userIdx = _.findIndex(this.users, function(candidateUser) {
        return candidateUser.id === user.userId;
    });

    if (userIdx === -1) {
        return callback(null, null);
    }

    var updated = _.clone(user);
    this.users[userIdx] = updated;
    return callback(null, updated);
};

FakeUserStore.prototype.remove = function(userId, callback) {
    _.remove(this.users, function(user) {
        return user.id === userId;
    });
    callback(null);
};

FakeUserStore.prototype.findByEmail = function(email, callback) {
    var found = _findByEmail.call(this, email);
    callback(null, found);
};

function _findByEmailSync(email) {
    return _.find(this.users, function(user) {
        return user.email === email;
    });
}

module.exports = FakeUserStore;
*/