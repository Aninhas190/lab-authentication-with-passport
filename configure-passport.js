'use strict';

const passport = require('passport');
const passportLocal = require('passport-local');

const bcrypt = require('bcryptjs');
// Passport Strategy configuration
const PassportLocalStrategy = passportLocal.Strategy;

const User = require('./models/user');
//define a serialization and deserialization process

passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then(user => callback(null, user))
    .catch(error => callback(error));
});

//user sign Up
passport.use(
  'sign-up',
  new PassportLocalStrategy({}, (username, password, callback) => {
    bcrypt
      .hash(password, 5)
      .then(hashAndSalt => {
        return User.create({
          username,
          passwordHash: hashAndSalt
        });
      })
      .then(user => callback(null, user))
      .catch(error => callback(error));
  })
);

//user sign-in
passport.use('sign-in', 
  new PassportLocalStrategy({}, (username, password, callback) => {
    let user;
    User.findOne({username})
    .then(document => {
      user = document;
      return bcrypt.compare(password, user.passwordHash);
    })
    .then(result => {
      if (result) {
        callback(null, user);
      } else {
        return Promisse.reject(new Error('Password does not match'));
      }
    })
    .catch(error => callback(error));
  })
);
