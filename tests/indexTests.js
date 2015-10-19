'use strict';

const chai = require('chai');
const assert = chai.assert;

const UserStoreFake = require('./fakes/userStoreFake');
const TokenStoreFake = require('./fakes/tokenStoreFake');
const EmailServiceFake = require('./fakes/emailServiceFake');
const hashAlgoFake = require('./fakes/hashAlgoFake');

const LocalAuth = require('../lib/index');

describe('Index', function() {

    it('has instance methods gathered from underlying services', function() {

        const userStoreFake = new UserStoreFake();
        const verifyEmailTokenStoreFake = new TokenStoreFake();
        const passwordResetTokenStoreFake = new TokenStoreFake();
        const emailServiceFake = new EmailServiceFake();

        const sut = new LocalAuth(
            userStoreFake,
            hashAlgoFake,
            emailServiceFake,
            verifyEmailTokenStoreFake,
            passwordResetTokenStoreFake);

        assert.isFunction(sut.register);

        assert.isFunction(sut.changePassword);

        assert.isFunction(sut.requestPasswordReset);
    });
});