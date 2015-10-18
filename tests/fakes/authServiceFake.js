'use strict';

class AuthServiceFake {
    constructor() {
        this.loggedInUser = null;
    }
    markLoggedIn(user) {
        this.loggedInUser = user;
        return Promise.resolve();
    }
    getLoggedInUserDetails() {
        if (!this.loggedInUser) {
            return Promise.resolve(null);
        }
        return Promise.resolve({
            id: this.loggedInUser.id,
            email: this.loggedInUser.email
        });
    }
    logOut(user) {
        this.loggedInUser = null;
        return Promise.resolve();
    }
}

module.exports = AuthServiceFake;