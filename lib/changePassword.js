'use strict';

const assert = require('./utils/assert');
const vutils = require('./utils/validationUtils');
const schemas = require('./schemas');
const co = require('co');
const ValidationError = require('./errors/validationError');
const AuthenticationError = require('./errors/authenticationError');
const debug = require('debug')('nla-changepassword');

class ChangePassword {
    constructor(userStore, hashAlgo, emailService) {
        this.userStore = assert(userStore, 'userStore');
        this.hashAlgo = assert(hashAlgo, 'hashAlgo');
        this.emailService = assert(emailService, 'emailService');
    }
    changePassword(loggedInUserEmail, oldPassword, newPassword, confirmNewPassword, optionalTenantId) {
        if (!loggedInUserEmail) {
            return Promise.reject(new AuthenticationError('Unauthenticated'));
        }
        try {
            const vOldPassword = vutils.assertValid(schemas.password.required().validate(oldPassword), 'Old password required');
            const vNewPassword = vutils.assertValid(schemas.password.required().validate(newPassword), 'New password required');
            const vConfirmNewPassword = vutils.assertValid(schemas.password.required().validate(confirmNewPassword), 'New password confirmation required');

            if (vNewPassword !== vConfirmNewPassword) {
                return Promise.reject(new ValidationError('New password and confirm password do not match'));
            }

            const self = this;
            return co(function *() {
                const user = yield self.userStore.getByEmail(loggedInUserEmail, optionalTenantId);
                if (!user) {
                    throw new ValidationError('Could not find user');
                }

                const oldPwdOk = yield self.hashAlgo.verify(vOldPassword, user.hashedPassword);
                if (!oldPwdOk) {
                    return Promise.reject(new ValidationError('Incorrect password'));
                }

                const hashedPassword = yield self.hashAlgo.hash(vNewPassword);
                yield self.userStore.setHashedPassword(user, hashedPassword, optionalTenantId);

                yield self.emailService.sendPasswordSuccessfullyChangedEmail(user, optionalTenantId);
            });
        } catch (e) {
            return Promise.reject(e);
        }
    }
}

module.exports = ChangePassword;