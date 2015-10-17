'use strict';

class AuthServiceFake {
    constructor() {
        this.loggedInUser = null;
    }
    markLoggedIn(user) {
        this.loggedInUser = user;
        return Promise.resolve();
    }
    getLoggedInUser() {
        return Promise.resolve(this.loggedInUser);
    }
    logOut(user) {
        this.loggedInUser = null;
        return Promise.resolve();
    }
}

module.exports = AuthServiceFake;