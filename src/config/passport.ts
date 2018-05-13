import * as passport from 'passport';
import * as request from 'request';
import * as passportLocal from 'passport-local';
import * as FacebookTokenStrategy from 'passport-facebook-token';
const InstagramTokenStrategy = require('passport-instagram-token');
const GoogleTokenStrategy = require('passport-google-token').Strategy;

import * as _ from 'lodash';

import { default as User, UserModel } from '../models/User';
import { Request, Response, NextFunction } from 'express';
import { access } from 'fs';

const LocalStrategy = passportLocal.Strategy;

/**
 * Sign in using Email and Password.
 */

export let local = new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    User.findOne({ email: email.toLowerCase() }, (err, user: any) => {
        if (err) { return done(err); }
        if (!user) {
        return done(undefined, false, { message: `Email ${email} not found.` });
        }
        user.comparePassword(password, (err: Error, isMatch: boolean) => {
        if (err) { return done(err); }
        if (isMatch) {
            return done(undefined, user);
        }
        return done(undefined, false, { message: 'Invalid email or password.' });
        });
    });
});

export let facebook = new FacebookTokenStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
}, (accessToken: string, refreshToken: string, profile: any, done: any) => {
    profile = profile._json;

    done(undefined, {
        accessToken: accessToken,
        profile: profile
    });
});

export let instagram = new InstagramTokenStrategy({
    clientID: process.env.INSTAGRAM_ID,
    clientSecret: process.env.INSTAGRAM_SECRET
}, (accessToken: any, refreshToken: string, profile: any, done: any) => {
    profile = profile._json.data;

    done(undefined, {
        accessToken: accessToken,
        profile: profile
    });
});

export let google = new GoogleTokenStrategy({
    clientID: process.env.GOOGLE_ID,
    clientSecret: process.env.GOOGLE_SECRET,
}, (accessToken: string, refreshToken: string, profile: any, done: any) => {
    profile = profile._json;

    done(undefined, {
        accessToken: accessToken,
        profile: profile
    });
});
