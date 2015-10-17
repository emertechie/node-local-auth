module.exports = {
    hash(str) {
        return Promise.resolve('hashed:' + str);
    },
    verify(str, hashed) {
        return Promise.resolve('hashed:' + str === hashed);
    }
};
