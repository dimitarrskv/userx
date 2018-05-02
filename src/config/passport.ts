import * as passport from 'passport';
import * as request from 'request';
import * as passportLocal from 'passport-local';
import * as FacebookTokenStrategy from 'passport-facebook-token';
const InstagramTokenStrategy = require('passport-instagram-token');
const GoogleTokenStrategy = require('passport-google-token').Strategy;
const LinkedInTokenStrategy = require('passport-linked-in-token').default;

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

export let linkedIn = new LinkedInTokenStrategy({
    clientID: process.env.LINKED_IN_ID,
    clientSecret: process.env.LINKED_IN_SECRET
}, (accessToken: string, refreshToken: string, profile: any, done: any) => {
    profile = profile._json;

    User.findOne({ email: profile.email }, (err, existingUser) => {
        if (err) { return done(err); }
        if (existingUser) {
            return done(undefined, existingUser);
        }
        User.findOne({ email: profile.email }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                console.log('existing user');
                done(err);
            } else {
                const user: any = new User();
                user.email = profile.email;
                user.google = profile.id;
                user.tokens.push({ kind: 'linkedIn', accessToken });
                user.profile.name = profile.name;
                user.profile.picture = profile.picture;
                user.save((err: Error) => {
                    done(err, user);
                });
            }
        });
    });
});