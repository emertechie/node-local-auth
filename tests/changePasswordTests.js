'use strict';

const chai = require('chai');
const assert = chai.assert;
const UserStoreFake = require('./fakes/userStoreFake');
const TokenStoreFake = require('./fakes/tokenStoreFake');
const EmailServiceFake = require('./fakes/emailServiceFake');
const hashAlgoFake = require('./fakes/hashAlgoFake');
const Registration = require('../lib/registration');
const ChangePassword = require('../lib/changePassword');
const _ = require('lodash');
const testUtils = require('./testUtils');

describe('Change Password', () => {
    let userStoreFake;
    let verifyEmailTokenStoreFake;
    let passwordResetTokenStoreFake;
    let emailServiceFake;
    let registration;

    const existingUserEmail = 'foo@example.com';
    const existingUserPassword = 'bar';
    const ValidNewPassword = 'password';

    let sut;
    let loggedInUserEmail;

    beforeEach(function*() {
        userStoreFake = new UserStoreFake();
        verifyEmailTokenStoreFake = new TokenStoreFake();
        passwordResetTokenStoreFake = new TokenStoreFake();
        emailServiceFake = new EmailServiceFake();

        sut = createSut();

        const user = yield registerUser(existingUserEmail, existingUserPassword);
        loggedInUserEmail = user.email;
    });

    function createSut(options, services) {
        const opts = _.merge({
            userStore: userStoreFake,
            verifyEmailTokenStore: verifyEmailTokenStoreFake,
            passwordResetTokenStore: passwordResetTokenStoreFake,
            hashAlgo: hashAlgoFake,
            emailService: emailServiceFake
        }, services);

        registration = new Registration(
            opts.userStore,
            opts.verifyEmailTokenStore,
            opts.hashAlgo,
            opts.emailService,
            options
        );

        return new ChangePassword(
            opts.userStore,
            opts.hashAlgo,
            opts.emailService,
            options);
    }

    it('ensures user is logged in', function *() {
        const loggedInUserEmail = null;

        const err = yield testUtils.assertThrows(function *() {
            yield sut.changePassword(loggedInUserEmail, existingUserPassword, ValidNewPassword, ValidNewPassword);
        });

        assert.equal(err.message, 'Unauthenticated');
    });

    it('requires existing password', function *() {
        const existingPassword = '';
        const err = yield testUtils.assertThrows(function *() {
            yield sut.changePassword(loggedInUserEmail, existingPassword, ValidNewPassword, ValidNewPassword);
        });

        assert.equal(err.message, 'Old password required');
    });

    it('requires new password', function *() {
        const newPassword = '';
        const err = yield testUtils.assertThrows(function *() {
            yield sut.changePassword(loggedInUserEmail, existingUserPassword, newPassword, ValidNewPassword);
        });

        assert.equal(err.message, 'New password required');
    });

    it('requires new password confirmation', function *() {
        const newConfirmPassword = '';
        const err = yield testUtils.assertThrows(function *() {
            yield sut.changePassword(loggedInUserEmail, existingUserPassword, ValidNewPassword, newConfirmPassword);
        });

        assert.equal(err.message, 'New password confirmation required');
    });

    it('ensures new password and new password confirmation match', function *() {
        const newPassword = 'foo';
        const newConfirmPassword = 'bar';
        const err = yield testUtils.assertThrows(function *() {
            yield sut.changePassword(loggedInUserEmail, existingUserPassword, newPassword, newConfirmPassword);
        });

        assert.equal(err.message, 'New password and confirm password do not match');
    });

    it('forbids password change given incorrect existing password', function *() {
        const incorrectPwd = existingUserPassword + 'X';
        const err = yield testUtils.assertThrows(function *() {
            yield sut.changePassword(loggedInUserEmail, incorrectPwd, ValidNewPassword, ValidNewPassword);
        });

        assert.equal(err.message, 'Incorrect password');
    });

    it('allows changing password given correct existing password', function *() {
        assert.lengthOf(userStoreFake.users, 1, '1 user registered');

        yield sut.changePassword(loggedInUserEmail, existingUserPassword, 'new-password', 'new-password');

        assert.lengthOf(userStoreFake.users, 1, 'Still 1 user registered');
        const user = userStoreFake.users[0];
        assert.equal(user.hashedPassword, 'hashed:new-password');
    });

    it('emails user when password changed', function *() {
        assert.lengthOf(emailServiceFake.calls.sendPasswordSuccessfullyChangedEmail, 0);

        yield sut.changePassword(loggedInUserEmail, existingUserPassword, 'new-password', 'new-password');

        assert.lengthOf(emailServiceFake.calls.sendPasswordSuccessfullyChangedEmail, 1);
        const args = emailServiceFake.calls.sendPasswordSuccessfullyChangedEmail[0];
        const user = args[0];
        assert.equal(user.email, existingUserEmail);
    });

    function *registerUser(email, password) {
        return yield registration.register(email, password);
    }
});
