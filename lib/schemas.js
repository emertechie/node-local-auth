const Joi = require('joi');

const schemas = {
    email: Joi.string().email(),
    password: Joi.string(),
    username: Joi.string().max(50),
    token: Joi.string().max(50)
};

module.exports = schemas;