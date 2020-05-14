'use strict';

const passport = require('passport');
const passportLocal = require('passport-local');
const passportGithub = require('passport-github');

const bcrypt = require('bcryptjs');
// Passport Strategy configuration
const PassportLocalStrategy = passportLocal.Strategy;
const PassportGithubStrategy = passportGithub.Strategy;

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

//social Log in
passport.use(
  new PassportGithubStrategy({
    clientID: process.env.GITHUB_API_CLIENT_ID,
    clientSecret: process.env.GITHUB_API_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/authentication/github-callback'
  }, (accessToken, refreshToken, profile, callback) => {
    const name = profile.displayName;
    const photo = profile._json.avatar_url;
    const githubId = profile.id;
  
    User.findOne({githubId})
      .then(user => {
        if (!user) {
          return User.create({ name, photo, githubId });
        } else {
          return Promise.resolve(user);
        }
      })
      .then(user => callback(null, user))
      .catch(error => callback(error));
    }
  )
);

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
        return Promise.reject(new Error('Password does not match'));
      }
    })
    .catch(error => callback(error));
  })
);
