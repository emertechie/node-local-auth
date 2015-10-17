'use strict';

const chai = require('chai');
const assert = chai.assert;
const UserStoreFake = require('./fakes/userStoreFake');
const TokenStoreFake = require('./fakes/tokenStoreFake');
const AuthServiceFake = require('./fakes/authServiceFake');
const EmailServiceFake = require('./fakes/emailServiceFake');
const hashAlgoFake = require('./fakes/hashAlgoFake');
const Registration = require('../lib/registration');
const ForgotPassword = require('../lib/forgotPassword.js');
const _ = require('lodash');
const testUtils = require('./testUtils');

describe('Forgot Password', () => {
    let userStoreFake;
    let verifyEmailTokenStoreFake;
    let passwordResetTokenStoreFake;
    let authServiceFake;
    let emailServiceFake;
    let registration;

    const existingUserEmail = 'foo@example.com';
    const existingUserPassword = 'bar';

    let sut;
    beforeEach(() => {
        userStoreFake = new UserStoreFake();
        verifyEmailTokenStoreFake = new TokenStoreFake();
        passwordResetTokenStoreFake = new TokenStoreFake();
        authServiceFake = new AuthServiceFake();
        emailServiceFake = new EmailServiceFake();

        sut = createSut();
    });

    function createSut(options, services) {
        const opts = _.merge({
            userStore: userStoreFake,
            userIdGetter: UserStoreFake.userIdGetter,
            authService: authServiceFake,
            verifyEmailTokenStore: verifyEmailTokenStoreFake,
            passwordResetTokenStore: passwordResetTokenStoreFake,
            hashAlgo: hashAlgoFake,
            emailService: emailServiceFake
        }, services);

        registration = new Registration(
            opts.userStore,
            opts.userIdGetter,
            opts.authService,
            opts.verifyEmailTokenStore,
            opts.hashAlgo,
            opts.emailService,
            options
        );

        return new ForgotPassword(
            opts.userStore,
            opts.userIdGetter,
            opts.authService,
            opts.passwordResetTokenStore,
            opts.hashAlgo,
            opts.emailService,
            options);
    }

    describe('Step 1 - Requesting Reset', () => {

        it('requires valid email', function *() {
            const email = '';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.requestReset(email);
            });

            assert.equal(err.message, 'Valid email address required');
        });

        it('sends forgot password email for existing account on entering matching email', function *() {
            yield registerUser(existingUserEmail, existingUserPassword);
            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 0, 'no calls yet');

            yield sut.requestReset(existingUserEmail);

            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 1, 'forgot password email sent');
            const callArgs = emailServiceFake.calls.sendForgotPasswordEmail[0];
            assert.equal(callArgs[0].email, existingUserEmail);
            const token = callArgs[1];
            assert.ok(token, 'has token');
        });

        it('ignores case of email when sending forgot password email', function *() {
            yield registerUser('foo@example.com', existingUserPassword);
            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 0, 'no calls yet');

            yield sut.requestReset('FoO@EXAMPLE.com');

            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 1, 'forgot password email sent');
            const callArgs = emailServiceFake.calls.sendForgotPasswordEmail[0];
            assert.equal(callArgs[0].email, 'foo@example.com');
        });

        it('can send forgot password attempt notification email on entering unknown email', function *() {
            yield registerUser('foo@example.com', existingUserPassword);
            assert.equal(emailServiceFake.calls.handleForgotPasswordForUnregisteredEmail.length, 0, 'no calls yet');

            yield sut.requestReset('unknown@example.com');

            assert.equal(emailServiceFake.calls.handleForgotPasswordForUnregisteredEmail.length, 1, 'handled unknown email');
            const callArgs = emailServiceFake.calls.handleForgotPasswordForUnregisteredEmail[0];
            assert.equal(callArgs[0], 'unknown@example.com');
        });

        it('stores new password reset token for email', function *() {
            yield registerUser(existingUserEmail, existingUserPassword);
            assert.lengthOf(passwordResetTokenStoreFake.tokens, 0, 'no stored token yet');

            yield sut.requestReset(existingUserEmail);

            assert.lengthOf(passwordResetTokenStoreFake.tokens, 1, 'stores token');

            const tokenDetails = passwordResetTokenStoreFake.tokens[0];
            assert.equal(tokenDetails.email, existingUserEmail);
            assert.equal(tokenDetails.userId, "User#1");
            assert.isNotNull(tokenDetails.hashedToken);
            assert.isNotNull(tokenDetails.expiry);
        });

        it('ensures password reset token does not contain any user identifiers to prevent guessing', function *() {
            const email = 'user@example.com';
            yield registerUser(email, existingUserPassword);
            yield sut.requestReset(email);

            const user = userStoreFake.users[0];
            assert.equal(user.id, 'User#1');

            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 1, 'forgot password email sent');

            const callArgs = emailServiceFake.calls.sendForgotPasswordEmail[0];
            const token = callArgs[1];
            assert.ok(token, 'Has token');
            // makes sure token does not contain 'user' - which covers email address and user id
            assert.isFalse(token.toLowerCase().includes('user'), 'Token does not contain "user"');
        });

        it('deletes any pending reset tokens for same email on receipt of a new password reset request', function *() {
            yield registerUser(existingUserEmail, existingUserPassword);
            yield sut.requestReset(existingUserEmail);

            assert.lengthOf(passwordResetTokenStoreFake.tokens, 1);
            assert.equal(passwordResetTokenStoreFake.tokens[0].tokenId, 'Token#1');

            yield sut.requestReset(existingUserEmail);

            assert.lengthOf(passwordResetTokenStoreFake.tokens, 1);
            assert.equal(passwordResetTokenStoreFake.tokens[0].tokenId, 'Token#2');
        });
    });

    describe('Step 1 - Requesting Reset (when email verification required)', () => {

        beforeEach(function() {
            sut = createSut({
                verifyEmail: true
            });
        });

        it('forbids resetting password if user email not previously verified', function *() {
            assert.lengthOf(userStoreFake.users, 0);

            yield registerUser(existingUserEmail, existingUserPassword);

            assert.lengthOf(userStoreFake.users, 1);
            assert.isFalse(userStoreFake.users[0].emailVerified, 'emailVerified is false');

            const err = yield testUtils.assertThrows(function *() {
                yield sut.requestReset(existingUserEmail);
            });

            assert.equal(err.message, 'Please verify your email address first by clicking on the link in the registration email');
        });

        it('sends forgot password email if user email previously verified', function *() {
            assert.lengthOf(userStoreFake.users, 0);

            yield registerUser(existingUserEmail, existingUserPassword);

            assert.lengthOf(userStoreFake.users, 1);
            // Mark email verified (this functionality tested elsewhere)
            // TODO: use proper call here
            userStoreFake.users[0].emailVerified = true;

            yield sut.requestReset(existingUserEmail);

            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 1, 'forgot password email sent');
            const callArgs = emailServiceFake.calls.sendForgotPasswordEmail[0];
            assert.equal(callArgs[0].email, existingUserEmail);
        });
    });

    describe('Step 2 - Verifying Token (when rendering password reset page)', () => {

        let passwordResetToken;

        beforeEach(function *() {
            // Set up existing pwd reset request and capture token:
            yield registerUser(existingUserEmail, existingUserPassword);
            yield sut.requestReset(existingUserEmail);

            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 1, 'forgot password email sent');
            const callArgs = emailServiceFake.calls.sendForgotPasswordEmail[0];
            passwordResetToken = callArgs[1];
        });

        it('ensures email is required', function *() {
            const email = '';
            const token = 'foo';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.assertTokenValid(email, token);
            });

            assert.equal(err.message, 'Valid email address required');
        });

        it('ensures token is required', function *() {
            const token = '';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.assertTokenValid(existingUserEmail, token);
            });

            assert.equal(err.message, 'Password reset token required');
        });

        it('ensures invalid password request tokens are ignored', function *() {
            const token = 'unknown';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.assertTokenValid(existingUserEmail, token);
            });

            assert.equal(err.message, 'Unknown or expired token');
        });

        it('ensures that password reset request is only valid for limited period of time', function *() {
            // expire the existing token:
            assert.lengthOf(passwordResetTokenStoreFake.tokens, 1);
            passwordResetTokenStoreFake.tokens[0].expiry = new Date(Date.now() - 1);

            const err = yield testUtils.assertThrows(function *() {
                yield sut.assertTokenValid(existingUserEmail, passwordResetToken);
            });

            assert.equal(err.message, 'Unknown or expired token');
        });

        it('does not throw if password reset token is valid', function *() {
            yield sut.assertTokenValid(existingUserEmail, passwordResetToken);
        });

        it('ignores email case when checking if password reset token is valid', function *() {
            yield sut.assertTokenValid(existingUserEmail.toUpperCase(), passwordResetToken);
        });
    });

    describe('Step 3 - Resetting Password', () => {

        const ValidPassword = 'password';
        const ValidToken = 'foo';
        let passwordResetToken;

        beforeEach(function *() {
            // Set up existing pwd reset request and capture token:
            yield registerUser(existingUserEmail, existingUserPassword);
            yield sut.requestReset(existingUserEmail);

            assert.equal(emailServiceFake.calls.sendForgotPasswordEmail.length, 1, 'forgot password email sent');
            const callArgs = emailServiceFake.calls.sendForgotPasswordEmail[0];
            passwordResetToken = callArgs[1];
        });

        it('ensures email is required', function *() {
            const email = '';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(email, ValidToken, ValidPassword, ValidPassword);
            });

            assert.equal(err.message, 'Valid email address required');
        });

        it('ensures token is required', function *() {
            const token = '';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(existingUserEmail, token, ValidPassword, ValidPassword);
            });

            assert.equal(err.message, 'Password reset token required');
        });

        it('ensures password is required', function *() {
            const password = '';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(existingUserEmail, passwordResetToken, password, ValidPassword);
            });

            assert.equal(err.message, 'New password required');
        });

        it('ensures confirm password is required', function *() {
            const confirmPassword = '';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(existingUserEmail, passwordResetToken, ValidPassword, confirmPassword);
            });

            assert.equal(err.message, 'Password confirmation required');
        });

        it('ensures password matches confirm password', function *() {
            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(existingUserEmail, passwordResetToken, 'password', 'confirm-password');
            });

            assert.equal(err.message, 'Password and confirm password do not match');
        });

        it('ensures unknown password request tokens are ignored', function *() {
            const token = 'unknown-token';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(existingUserEmail, token, ValidPassword, ValidPassword);
            });

            assert.equal(err.message, 'Unknown or expired token');
        });

        it('ensures that expired tokens are ignored', function *() {
            // expire the existing token:
            assert.lengthOf(passwordResetTokenStoreFake.tokens, 1);
            passwordResetTokenStoreFake.tokens[0].expiry = new Date(Date.now() - 1);

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(existingUserEmail, passwordResetToken, ValidPassword, ValidPassword);
            });

            assert.equal(err.message, 'Unknown or expired token');
        });

        it('ensures unknown password request emails are ignored', function *() {
            const email = 'unknown-email@example.com';

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(email, passwordResetToken, ValidPassword, ValidPassword);
            });

            assert.equal(err.message, 'Unknown or expired token');
        });

        it('ensures password reset tokens for unknown users are ignored', function *() {
            // Just remove all users so no possibility of a match:
            userStoreFake.users = [];

            const err = yield testUtils.assertThrows(function *() {
                yield sut.resetPassword(existingUserEmail, passwordResetToken, ValidPassword, ValidPassword);
            });

            assert.equal(err.message, 'Unknown or expired token');
        });

        it('allows password to be reset', function *() {
            const newPassword = existingUserPassword + '-new';

            yield sut.resetPassword(existingUserEmail, passwordResetToken, newPassword, newPassword);

            assert.lengthOf(userStoreFake.users, 1);
            var user = userStoreFake.users[0];
            assert.equal(user.hashedPassword, 'hashed:' + newPassword);
        });

        it('ignores case of email when resetting password', function *() {
            const newPassword = existingUserPassword + '-new';
            const uppercaseEmail = existingUserEmail.toUpperCase();

            yield sut.resetPassword(uppercaseEmail, passwordResetToken, newPassword, newPassword);

            assert.lengthOf(userStoreFake.users, 1);
            var user = userStoreFake.users[0];
            assert.equal(user.hashedPassword, 'hashed:' + newPassword);
        });

        it('deletes password reset token after password reset', function *() {
            assert.lengthOf(passwordResetTokenStoreFake.tokens, 1);

            yield sut.resetPassword(existingUserEmail, passwordResetToken, ValidPassword, ValidPassword);

            assert.lengthOf(passwordResetTokenStoreFake.tokens, 0);
        });

        it('emails user confirmation of change after password reset', function *() {
            assert.lengthOf(emailServiceFake.calls.sendPasswordSuccessfullyResetEmail, 0);

            yield sut.resetPassword(existingUserEmail, passwordResetToken, ValidPassword, ValidPassword);

            assert.lengthOf(emailServiceFake.calls.sendPasswordSuccessfullyResetEmail, 1);
            const args = emailServiceFake.calls.sendPasswordSuccessfullyResetEmail[0];
            const user = args[0];
            assert.equal(user.email, existingUserEmail, 'Email sent to user');
        });
    });

    function *registerUser(email, password) {
        yield registration.register(email, password);
    }
});
