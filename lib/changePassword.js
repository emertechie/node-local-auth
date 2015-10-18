'use strict';

const assert = require('./utils/assert');
const vutils = require('./utils/validationUtils');
const schemas = require('./schemas');
const co = require('co');
const ValidationError = require('./errors/validationError');
const AuthenticationError = require('./errors/authenticationError');
const debug = require('debug')('nla-changepassword');

class ChangePassword {
    constructor(userStore, userIdGetter, authService, hashAlgo, emailService) {
        this.userStore = assert(userStore, 'userStore');
        this.userIdGetter = assert(userIdGetter, 'userIdGetter');
        this.authService = assert(authService, 'authService');
        this.hashAlgo = assert(hashAlgo, 'hashAlgo');
        this.emailService = assert(emailService, 'emailService');
    }
    changePassword(oldPassword, newPassword, confirmNewPassword) {
        try {
            const vOldPassword = vutils.assertValid(schemas.password.required().validate(oldPassword), 'Old password required');
            const vNewPassword = vutils.assertValid(schemas.password.required().validate(newPassword), 'New password required');
            const vConfirmNewPassword = vutils.assertValid(schemas.password.required().validate(confirmNewPassword), 'New password confirmation required');

            if (vNewPassword !== vConfirmNewPassword) {
                return Promise.reject(new ValidationError('New password and confirm password do not match'));
            }

            const self = this;
            return co(function *() {
                const loggedInUser = yield self.authService.getLoggedInUserDetails();
                if (!loggedInUser) {
                    throw new AuthenticationError('Unauthenticated');
                }

                const userId = self.userIdGetter(loggedInUser);
                const user = yield self.userStore.getById(userId);
                if (!user) {
                    throw new ValidationError('Could not find user');
                }

                const oldPwdOk = yield self.hashAlgo.verify(vOldPassword, user.hashedPassword);
                if (!oldPwdOk) {
                    return Promise.reject(new ValidationError('Incorrect password'));
                }

                user.hashedPassword = yield self.hashAlgo.hash(vNewPassword);

                yield self.userStore.update(user);

                yield self.emailService.sendPasswordSuccessfullyChangedEmail(user);
            });
        } catch (e) {
            return Promise.reject(e);
        }
    }
}

module.exports = ChangePassword;