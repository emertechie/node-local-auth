'use strict';

const assert = require('./utils/assert');
const vutils = require('./utils/validationUtils');
const schemas = require('./schemas');
const merge = require('lodash.merge');
const co = require('co');
const uuid = require('node-uuid');
const ValidationError = require('./errors/validationError');
const AuthenticationError = require('./errors/authenticationError');
const debug = require('debug')('nla-registration');

class Registration {
    constructor(userStore, userIdGetter, verifyEmailTokenStore, hashAlgo, emailService, options) {
        this.userStore = assert(userStore, 'userStore');
        this.userIdGetter = assert(userIdGetter, 'userIdGetter');
        this.verifyEmailTokenStore = assert(verifyEmailTokenStore, 'verifyEmailTokenStore');
        this.hashAlgo = assert(hashAlgo, 'hashAlgo');
        this.emailService = assert(emailService, 'emailService');

        this.options = merge({
            normalizeCase: true,
            verifyEmail: false
        }, options);
    }
    // NOTE: don't forget to mark user as logged in
    register(email, password, username) {
        try {
            let vEmail = vutils.assertValid(schemas.email.required().validate(email), 'Valid email address required');
            const vPassword = vutils.assertValid(schemas.password.required().validate(password), 'Password required');
            const vUsername = vutils.assertValid(schemas.username.optional().validate(username), 'Invalid username');

            const self = this;
            return co(function *() {
                vEmail = self.options.normalizeCase ? vEmail.toLowerCase() : vEmail;

                debug(`Registering "${vEmail}"`);
                var userForSave = yield createUserObj(vEmail, vPassword, vUsername, self.hashAlgo, self.options.verifyEmail);
                const user = yield self.userStore.add(userForSave);

                let verifyParams;
                if (self.options.verifyEmail) {
                    const unhashedToken = uuid.v4().replace(/-/g, '');
                    yield self.verifyEmailTokenStore.add({
                        email: email,
                        userId: self.userIdGetter(user),
                        hashedToken: yield self.hashAlgo.hash(unhashedToken)
                    });
                    debug(`Added verify email token for "${vEmail}" during registration`);
                    verifyParams = {
                        email: vEmail,
                        token: unhashedToken,
                        queryString: `?email=${vEmail}&token=${unhashedToken}`
                    };
                }

                yield self.emailService.sendRegistrationEmail({
                    email: vEmail,
                    username: vUsername
                }, verifyParams);

                return user;
            });
        } catch (e) {
            return Promise.reject(e);
        }
    }
    verifyEmail(email, token) {
        try {
            let vEmail = vutils.assertValid(schemas.email.required().validate(email), 'Valid email address required');
            let vToken = vutils.assertValid(schemas.token.required().validate(token), 'Verify email token required');

            const self = this;
            return co(function *() {
                vEmail = self.options.normalizeCase ? vEmail.toLowerCase() : vEmail;

                const tokenDetails = yield self.verifyEmailTokenStore.findByEmail(vEmail);
                if (!tokenDetails) {
                    debug(`Could not find verify email token using email "${vEmail}"`);
                    throw new ValidationError('Unknown or invalid token')
                }

                const verified = yield self.hashAlgo.verify(vToken, tokenDetails.hashedToken);
                if (!verified) {
                    debug(`Unknown or invalid verify email token "${vToken}" for email "${vEmail}"`);
                    throw new ValidationError('Unknown or invalid token');
                }

                const user = yield self.userStore.getByEmail(vEmail);

                if (!user) {
                    debug(`Unknown user "${vEmail}" for verify email token "${vToken}"`);
                    throw new ValidationError('Unknown or invalid token');
                }

                user.emailVerified = true;
                yield self.userStore.update(user);

                yield self.verifyEmailTokenStore.removeAllByEmail(vEmail);
                debug(`User "${vEmail}" successfully verified email`);
            });
        } catch (e) {
            return Promise.reject(e);
        }
    }
    // NOTE: don't forget to mark user as logged out also
    unregister(loggedInUserId) {
        if (!loggedInUserId) {
            return Promise.reject(new AuthenticationError('Unauthenticated'));
        }
        const self = this;
        return co(function *() {
            yield self.userStore.removeById(loggedInUserId);
            debug('User "${loggedInUser.email}" successfully unregistered');
        });
    }
}

function *createUserObj(vEmail, vPassword, vUsername, hashAlgo, verifyEmail) {
    const userDetails = {
        email: vEmail,
        hashedPassword: yield hashAlgo.hash(vPassword)
    };
    if (vUsername) {
        userDetails.username = vUsername;
    }
    if (verifyEmail) {
        userDetails.emailVerified = false;
    }
    return userDetails;
}

module.exports = Registration;