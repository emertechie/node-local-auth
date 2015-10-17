'use strict';

const assert = require('./utils/assert');
const vutils = require('./utils/validationUtils');
const schemas = require('./schemas');
const merge = require('lodash.merge');
const co = require('co');
const ValidationError = require('./errors/validationError');
const uuid = require('node-uuid');
const debug = require('debug')('nla-forgotpassword');

class ForgotPassword {
    constructor(userStore, userIdGetter, authService, passwordResetTokenStore, hashAlgo, emailService, options) {
        this.userStore = assert(userStore, 'userStore');
        this.userIdGetter = assert(userIdGetter, 'userIdGetter');
        this.authService = assert(authService, 'authService');
        this.passwordResetTokenStore = assert(passwordResetTokenStore, 'passwordResetTokenStore');
        this.hashAlgo = assert(hashAlgo, 'hashAlgo');
        this.emailService = assert(emailService, 'emailService');

        this.options = merge({
            normalizeCase: true,
            verifyEmail: false,
            tokenExpirationMins: 60
        }, options);
    }
    requestReset(email) {
        try {
            let vEmail = vutils.assertValid(schemas.email.required().validate(email), 'Valid email address required');

            const self = this;
            return co(function *() {
                vEmail = self.options.normalizeCase ? vEmail.toLowerCase() : vEmail;

                const user = yield self.userStore.getByEmail(vEmail);

                if (!user) {
                    debug(`Forgot password process attempted for unregistered email "${vEmail}"`);
                    if (self.emailService.handleForgotPasswordForUnregisteredEmail) {
                        yield self.emailService.handleForgotPasswordForUnregisteredEmail(vEmail);
                    }
                    return;
                }

                if (self.options.verifyEmail && !user.emailVerified) {
                    throw new ValidationError('Please verify your email address first by clicking on the link in the registration email');
                }

                yield self.passwordResetTokenStore.removeAllByEmail(vEmail);

                const unhashedToken = uuid.v4().replace(/-/g, '');
                yield self.passwordResetTokenStore.add({
                    email: vEmail,
                    userId: self.userIdGetter(user),
                    expiry: new Date(Date.now() + (self.options.tokenExpirationMins * 60 * 1000)),
                    hashedToken: yield self.hashAlgo.hash(unhashedToken)
                });

                debug(`Sending forgot password email for user "${vEmail}"`);
                yield self.emailService.sendForgotPasswordEmail(user, unhashedToken);
            });
        } catch (e) {
            return Promise.reject(e);
        }
    }
    assertTokenValid(email, token) {
        try {
            let vEmail = vutils.assertValid(schemas.email.required().validate(email), 'Valid email address required');
            let vToken = vutils.assertValid(schemas.token.required().validate(token), 'Password reset token required');

            const self = this;
            return co(function *() {
                vEmail = self.options.normalizeCase ? vEmail.toLowerCase() : vEmail;
                yield _findAndVerifyPasswordResetToken.call(self, vEmail, vToken);
            });
        } catch (e) {
            return Promise.reject(e);
        }
    }
    resetPassword(email, token, password, confirmPassword) {
        try {
            let vEmail = vutils.assertValid(schemas.email.required().validate(email), 'Valid email address required');
            const vToken = vutils.assertValid(schemas.token.required().validate(token), 'Password reset token required');
            const vPassword = vutils.assertValid(schemas.password.required().validate(password), 'New password required');
            const vConfirmPassword = vutils.assertValid(schemas.password.required().validate(confirmPassword), 'Password confirmation required');

            if (vPassword !== vConfirmPassword) {
                return Promise.reject(new ValidationError('Password and confirm password do not match'));
            }

            const self = this;
            return co(function *() {
                vEmail = self.options.normalizeCase ? vEmail.toLowerCase() : vEmail;

                const tokenDetails = yield _findAndVerifyPasswordResetToken.call(self, vEmail, vToken);

                const user = yield self.userStore.getById(tokenDetails.userId);
                if (!user) {
                    throw new ValidationError('Unknown or expired token');
                }

                user.hashedPassword = yield self.hashAlgo.hash(vPassword);
                yield self.userStore.update(user);

                yield self.passwordResetTokenStore.removeAllByEmail(tokenDetails.email);

                yield self.emailService.sendPasswordSuccessfullyResetEmail(user);
            });
        } catch (e) {
            return Promise.reject(e);
        }
    }
}

function *_findAndVerifyPasswordResetToken(email, token) {
    const tokenDetails = yield this.passwordResetTokenStore.findByEmail(email);

    var isValidStep1 =
        tokenDetails &&
        tokenDetails.hashedToken &&
        tokenDetails.expiry &&
        tokenDetails.expiry instanceof Date &&
        tokenDetails.expiry.getTime() >= Date.now();

    if (!isValidStep1 || !(yield this.hashAlgo.verify(token, tokenDetails.hashedToken))) {
        throw new ValidationError('Unknown or expired token');
    }

    return tokenDetails;
}

module.exports = ForgotPassword;