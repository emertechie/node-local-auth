'use strict';

const chai = require('chai');
//chai.use(require('chai-shallow-deep-equal'));
const assert = chai.assert;
const UserStoreFake = require('./fakes/userStoreFake');
const TokenStoreFake = require('./fakes/tokenStoreFake');
const EmailServiceFake = require('./fakes/emailServiceFake');
const hashAlgoFake = require('./fakes/hashAlgoFake');
const Registration = require('../lib/registration');
const ValidationError = require('../lib/errors/validationError');
const DuplicateRegistrationError = require('../lib/errors/duplicateRegistrationError');
const _ = require('lodash');
const testUtils = require('./testUtils');

describe('Registration', () => {

    const ValidEmail = 'foo@example.com';
    const ValidUsername = 'username';
    const ValidPassword = 'password';

    let userStoreFake;
    let tokenStoreFake;
    let emailServiceFake;

    let sut;
    beforeEach(() => {
        userStoreFake = new UserStoreFake();
        tokenStoreFake = new TokenStoreFake();
        emailServiceFake = new EmailServiceFake();

        sut = createSut();
    });

    function createSut(options, services) {
        const opts = _.merge({
            userStore: userStoreFake,
            tokenStore: tokenStoreFake,
            hashAlgo: hashAlgoFake,
            emailService: emailServiceFake
        }, services);

        return new Registration(
            opts.userStore,
            opts.tokenStore,
            opts.hashAlgo,
            opts.emailService,
            options
        );
    }

    describe('User Registration', () => {

        it('should require email address', function *() {
            let expectedErr;
            try {
                const email = '';
                yield sut.register(email, ValidPassword, ValidUsername);
            } catch (e) {
                expectedErr = e;
            }
            assertError(expectedErr, ValidationError, 'Valid email address required');
        });

        it('should require valid email address', function *() {
            let expectedErr;
            try {
                const email = 'foo';
                yield sut.register(email, ValidPassword, ValidUsername);
            } catch (e) {
                expectedErr = e;
            }
            assertError(expectedErr, ValidationError, 'Valid email address required');
        });

        it('should require password', function *() {
            let expectedErr;
            try {
                const password = '';
                yield sut.register(ValidEmail, password, ValidUsername);
            } catch (e) {
                expectedErr = e;
            }
            assertError(expectedErr, ValidationError, 'Password required');
        });

        it('should allow registration with username, email and password', function *() {
            yield sut.register('foo@example.com', 'the-password', 'the-username');

            assert.lengthOf(userStoreFake.users, 1, 'User registered');
            assert.deepEqual(userStoreFake.users[0], {
                username: 'the-username',
                email: 'foo@example.com',
                id: "User#1",
                hashedPassword: 'hashed:the-password'
            });
        });

        it('should allow registration with just email and password', function *() {
            assert.lengthOf(userStoreFake.users, 0, 'No user registered yet');

            yield sut.register('foo@example.com', 'the-password');

            assert.lengthOf(userStoreFake.users, 1, 'User registered');
            assert.deepEqual(userStoreFake.users[0], {
                email: 'foo@example.com',
                id: "User#1",
                hashedPassword: 'hashed:the-password'
            });
        });

        it('should normalize the case of the email address when registering in order to avoid confusion', function *() {
            assert.lengthOf(userStoreFake.users, 0, 'No user registered yet');

            yield sut.register('FOO@EXAMPLE.COM', 'the-password');

            assert.lengthOf(userStoreFake.users, 1, 'User registered');
            assert.deepEqual(userStoreFake.users[0], {
                email: 'foo@example.com',
                hashedPassword: 'hashed:the-password',
                id: "User#1"
            });
        });

        it('should prevent same user registering more than once', function *() {
            yield sut.register('foo@example.com', 'the-password');

            let regErr;
            try {
                yield sut.register('foo@example.com', 'the-password');
            } catch (e) {
                regErr = e;
            }
            assertError(regErr, DuplicateRegistrationError, 'A user with that email address already exists');
        });

        it('should use email service to send registration email', function *() {
            assert.equal(emailServiceFake.calls.sendRegistrationEmail.length, 0, 'no calls yet');

            yield sut.register('foo@example.com', 'the-password', 'the-username');

            assert.equal(emailServiceFake.calls.sendRegistrationEmail.length, 1, 'reg email sent');
            const callArgs = emailServiceFake.calls.sendRegistrationEmail[0];
            const userDetails = callArgs[0];
            assert.deepEqual(userDetails, {
                email: 'foo@example.com',
                username: 'the-username'
            });
        });

        function assertError(err, ErrorType, expectedMsg) {
            assert.ok(err, 'Expect error');
            assert.instanceOf(err, ErrorType, 'error type');
            assert.equal(err.message, expectedMsg);
        }
    });

    describe('User Registration With Email Verification', () => {

        beforeEach(function() {
            sut = createSut({
                verifyEmail: true
            });
        });

        it('provides email address verification token when sending registration email', function *() {
            assert.equal(emailServiceFake.calls.sendRegistrationEmail.length, 0, 'no calls yet');

            yield sut.register('foo@example.com', 'the-password', 'the-username');

            assert.equal(emailServiceFake.calls.sendRegistrationEmail.length, 1, 'reg email sent');
            const verifyParams = emailServiceFake.calls.sendRegistrationEmail[0][1];

            assert.equal(verifyParams.email, 'foo@example.com');
            assert.ok(verifyParams.token, 'has a token');
            assert.equal(verifyParams.queryString, '?email=foo@example.com&token=' + verifyParams.token);
        });

        it('registers user with emailVerified property set to false initially', function *() {
            assert.lengthOf(userStoreFake.users, 0, 'No user registered yet');

            yield sut.register('foo@example.com', 'the-password');

            assert.lengthOf(userStoreFake.users, 1, 'User registered');
            const user = userStoreFake.users[0];
            assert.isFalse(user.emailVerified, 'emailVerified set to false');
        });

        describe('Verifying email', () => {

            it('requires email address when verifying email', function *() {
                const email = '';

                const err = yield testUtils.assertThrows(function *() {
                    yield sut.verifyEmail(email, 'the-token');
                });

                assert.equal(err.message, 'Valid email address required');
            });

            it('requires token address when verifying email', function *() {
                const token = '';

                const err = yield testUtils.assertThrows(function *() {
                    yield sut.verifyEmail('foo@example.com', token);
                });

                assert.equal(err.message, 'Verify email token required');
            });

            it('rejects attempt to verify email with invalid token', function *() {
                const invalidToken = 'unknown-token';

                const verifyParams = yield registerUserAndGetVerifyParams();

                const err = yield testUtils.assertThrows(function *() {
                    yield sut.verifyEmail(verifyParams.email, invalidToken);
                });

                assert.equal(err.message, 'Unknown or invalid token');
            });

            it('rejects attempt to verify email with token for unknown user', function *() {
                const verifyParams = yield registerUserAndGetVerifyParams();

                // Some time later, user deletes their account

                // Clear all users:
                userStoreFake.users.length = 0;

                const err = yield testUtils.assertThrows(function *() {
                    yield sut.verifyEmail(verifyParams.email, verifyParams.token);
                });

                assert.equal(err.message, 'Unknown or invalid token');
            });

            it('marks user email address verified given valid token', function *() {
                assert.lengthOf(userStoreFake.users, 0, 'No user registered yet');

                const verifyParams = yield registerUserAndGetVerifyParams();

                yield sut.verifyEmail(verifyParams.email, verifyParams.token);

                assert.lengthOf(userStoreFake.users, 1, 'User registered');
                const user = userStoreFake.users[0];
                assert.isTrue(user.emailVerified, 'emailVerified set to true');
            });

            it('ignores case of email address when verifying email address', function *() {
                assert.lengthOf(userStoreFake.users, 0, 'No user registered yet');

                const verifyParams = yield registerUserAndGetVerifyParams({
                    email: 'foo@example.com'
                });

                yield sut.verifyEmail('FoO@EXAMPLE.com', verifyParams.token);

                assert.lengthOf(userStoreFake.users, 1, 'User registered');
                const user = userStoreFake.users[0];
                assert.isTrue(user.emailVerified, 'emailVerified set to true');
            });

            it('removes email verification token after use', function *() {
                const verifyParams = yield registerUserAndGetVerifyParams();
                assert.lengthOf(tokenStoreFake.tokens, 1, 'token stored');

                yield sut.verifyEmail(verifyParams.email, verifyParams.token);

                assert.lengthOf(tokenStoreFake.tokens, 0, 'token removed');
            });

            function *registerUserAndGetVerifyParams(opts) {
                opts = opts || {};
                assert.equal(emailServiceFake.calls.sendRegistrationEmail.length, 0, 'no calls yet');

                yield sut.register(opts.email || 'foo@example.com', opts.password || 'the-password');

                assert.equal(emailServiceFake.calls.sendRegistrationEmail.length, 1, 'reg email sent');
                return emailServiceFake.calls.sendRegistrationEmail[0][1];
            }
        });
    });

    describe('User Unregistration', () => {

        it('attempting to unregister when not logged in will throw an AuthenticationError', function*() {
            const loggedInUserEmail = null;
            const err = yield testUtils.assertThrows(function *() {
                yield sut.unregister(loggedInUserEmail);
            });
            assert.equal(err.message, 'Unauthenticated')
        });

        it('should remove existing user from userStore when unregistering', function *() {
            assert.lengthOf(userStoreFake.users, 0, 'No user registered yet');
            const user = yield sut.register('foo@example.com', 'the-password');
            assert.lengthOf(userStoreFake.users, 1, 'User registered');

            yield sut.unregister(user.email);

            assert.lengthOf(userStoreFake.users, 0, 'User removed');
        });
    });
});
