'use strict';

class EmailServiceFake {
    constructor() {
        this.calls = {
            sendRegistrationEmail: [],
            sendForgotPasswordEmail: [],
            handleForgotPasswordForUnregisteredEmail: [],
            sendPasswordSuccessfullyResetEmail: [],
            sendPasswordSuccessfullyChangedEmail: []
        };
    }
    sendRegistrationEmail(userDetails, verifyParams) {
        this.calls.sendRegistrationEmail.push([userDetails, verifyParams]);
        return Promise.resolve();
    }
    sendForgotPasswordEmail(user, token) {
        this.calls.sendForgotPasswordEmail.push([user, token]);
        return Promise.resolve();
    }
    handleForgotPasswordForUnregisteredEmail(email) {
        this.calls.handleForgotPasswordForUnregisteredEmail.push([email]);
        return Promise.resolve();
    }
    sendPasswordSuccessfullyResetEmail(user) {
        this.calls.sendPasswordSuccessfullyResetEmail.push([user]);
        return Promise.resolve();
    }
    sendPasswordSuccessfullyChangedEmail(user) {
        this.calls.sendPasswordSuccessfullyChangedEmail.push([user]);
        return Promise.resolve();
    }
}

module.exports = EmailServiceFake;