'use strict';

/*
module.exports = {
    sendForgotPasswordEmail: function(user, token, cb) {
        cb(null);
    },
    sendForgotPasswordNotificationForUnregisteredEmail: function(email, cb) {
        cb(null);
    },
    sendPasswordSuccessfullyResetEmail: function(user, cb) {
        cb(null);
    },
    sendPasswordSuccessfullyChangedEmail: function(user, cb) {
        cb(null);
    }
};*/

class EmailServiceFake {
    constructor() {
        this.calls = {
            sendRegistrationEmail: []
        };
    }
    sendRegistrationEmail(userDetails, verifyParams) {
        this.calls.sendRegistrationEmail.push([userDetails, verifyParams]);
        return Promise.resolve();
    }
}

module.exports = EmailServiceFake;