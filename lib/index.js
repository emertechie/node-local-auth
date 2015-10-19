'use strict';

const assert = require('./utils/assert');
const Registration = require('./registration');
const ForgotPassword = require('./forgotPassword');
const ChangePassword = require('./changePassword');

class LocalAuth {
    constructor(
        userStore,
        hashAlgo,
        emailService,
        verifyEmailTokenStore,
        passwordResetTokenStore,
        options) {

        let services = [];
        if (verifyEmailTokenStore) {
            services.push(new Registration(userStore, verifyEmailTokenStore, hashAlgo, emailService, options));
        }
        if (passwordResetTokenStore) {
            services.push(new ForgotPassword(userStore, passwordResetTokenStore, hashAlgo, emailService, options));
        }
        services.push(new ChangePassword(userStore, hashAlgo, emailService));

        // Expose all service instance functions on this object
        services.forEach(svc => {
            let proto = Object.getPrototypeOf(svc);
            Object.getOwnPropertyNames(proto)
                .filter(x => x !== 'constructor')
                .filter(x => typeof svc[x] === 'function')
                .forEach(fnName => {
                    this[fnName] = svc[fnName].bind(svc);
                });
        });
    }
}

module.exports = LocalAuth;