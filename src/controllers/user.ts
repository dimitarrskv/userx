import * as async from 'async';
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import * as passport from 'passport';
import * as jwt from 'jsonwebtoken';
import * as expressJwt from 'express-jwt';
import { default as User, UserModel, AuthToken } from '../models/User';
import { Request, Response, NextFunction } from 'express';
import { LocalStrategyInfo } from 'passport-local';
import { WriteError } from 'mongodb';
const request = require('express-validator');
const paginate = require('express-paginate');

/**
 * POST /login
 * Sign in using email and password.
 */
export let login = (req: Request, res: Response, next: NextFunction) => {
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('password', 'Password cannot be blank').notEmpty();
    req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

    const errors = req.validationErrors();

    if (errors)
        return res.send(400, 'Invalid Request');

    passport.authenticate('local', (err: Error, user: UserModel, info: LocalStrategyInfo) => {
        if (err) { return next(err); }
        if (!user) {
            return res.send(401, 'User Not Authenticated');
        }

        req.user = user;
        req.auth = {
            id: req.user.id,
            name: req.user.name,
            email: req.user.email,
            picture: req.user.profile.picture
        };

        next();

    })(req, res, next);
};

export let createToken = function(auth: any) {
    return jwt.sign(auth, 'my-secret',
    {
        expiresIn: 60 * 120
    });
};

export let generateToken = (req: Request, res: Response, next: NextFunction) => {
    req.token = createToken(req.auth);
    next();
};

export let sendToken = (req: Request, res: Response) => {
    res.setHeader('Authorization', 'Bearer ' + req.token);
    res.status(200).send(req.auth);
};

export let authenticate = expressJwt({
    secret: 'my-secret',
    requestProperty: 'auth',
    getToken: function(req: any) {
      if (req.headers['authorization']) {
        return req.headers['authorization'].split('Bearer ')[1];
      }
      return undefined;
    }
});

export let oAuthlogin = (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
        return res.send(401, 'User Not Authenticated');
    }

    // prepare token for API
    req.auth = {
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        picture: req.user.profile.picture
    };

    next();
};

export let getProfile = (req: Request, res: Response, next: NextFunction) => {
    next();
};

export let getCurrentUser = (req: Request, res: Response, next: NextFunction) => {
    User.findById(req.auth.id, function(err, user) {
      if (err) {
        next(err);
      } else {
        req.user = user;
        next();
      }
    });
};

export let getOne = (req: Request, res: Response) => {
    const user = req.user.toObject();

    delete user['facebookProvider'];
    delete user['__v'];

    res.json(user);
};

export let updateProfile = (req: Request, res: Response, next: NextFunction) => {
    req.assert('email', 'Please enter a valid email address.').isEmail();
    req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

    const errors = req.validationErrors();

    if (errors)
        return res.send(400, 'Invalid Request');

    User.findById(req.user.id, (err, user: UserModel) => {
        if (err) { return next(err); }
        user.email = req.body.email || '';
        user.profile.name = req.body.name || '';
        user.profile.gender = req.body.gender || '';
        user.profile.location = req.body.location || '';
        user.profile.website = req.body.website || '';
        user.save((err: WriteError) => {
            if (err) {
                if (err.code === 11000) {
                    res.send(400, 'The email address you have entered is already associated with an account.');
                }
                return next(err);
            }
            res.json(user);
        });
    });
};

export let updatePassword = (req: Request, res: Response, next: NextFunction) => {
    req.assert('password', 'Password must be at least 4 characters long').len({ min: 4 });
    req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);

    const errors = req.validationErrors();

    if (errors)
        return res.send(400, 'Invalid Request');

    User.findById(req.user.id, (err, user: UserModel) => {
        if (err) { return next(err); }
        user.password = req.body.password;
        user.save((err: WriteError) => {
            if (err) { return next(err); }
            res.json(user);
        });
    });
};

export let list = (req: Request, res: Response, next: NextFunction) => {

    const limit = parseInt(req.query.limit);
    const skip = (parseInt(req.query.page) - 1) * limit;
    const filter = req.query.filter ? {
        $or: [
            { email: {$regex : '^' + req.query.filter } },
            { name: {$regex : '^' + req.query.filter } }]
    } : {};
    return Promise.all([
        User.find(filter).limit(limit).skip(skip).lean().exec(),
        User.count(filter)
    ])
    .then(result => {
        res.send({
            data: result[0],
            flags: {
                count: result[1]
            }
        });
    })
    .catch(err => {
        next(err);
    });
};

export let bulkCreate = (req: Request, res: Response, next: NextFunction) => {
    const users = [
        { email: 'dimitar.rskv+1@gmail.com', name: 'Dimitar Ruskov1', password: '123asd'},
        { email: 'dimitar.rskv+2@gmail.com', name: 'Dimitar Ruskov2', password: '123asd'},
        { email: 'dimitar.rskv+3@gmail.com', name: 'Dimitar Ruskov3', password: '123asd'},
        { email: 'dimitar.rskv+4@gmail.com', name: 'Dimitar Ruskov4', password: '123asd'},
        { email: 'dimitar.rskv+5@gmail.com', name: 'Dimitar Ruskov5', password: '123asd'},
        { email: 'dimitar.rskv+6@gmail.com', name: 'Dimitar Ruskov6', password: '123asd'},
        { email: 'dimitar.rskv+7@gmail.com', name: 'Dimitar Ruskov7', password: '123asd'},
        { email: 'dimitar.rskv+8@gmail.com', name: 'Dimitar Ruskov8', password: '123asd'},
        { email: 'dimitar.rskv+9@gmail.com', name: 'Dimitar Ruskov9', password: '123asd'},
        { email: 'dimitar.rskv+11@gmail.com', name: 'Dimitar Ruskov10', password: '123asd'},
        { email: 'dimitar.rskv+12@gmail.com', name: 'Dimitar Ruskov12', password: '123asd'},
        { email: 'dimitar.rskv+13@gmail.com', name: 'Dimitar Ruskov13', password: '123asd'},
        { email: 'dimitar.rskv+14@gmail.com', name: 'Dimitar Ruskov14', password: '123asd'},
        { email: 'dimitar.rskv+15@gmail.com', name: 'Dimitar Ruskov15', password: '123asd'},
        { email: 'dimitar.rskv+16@gmail.com', name: 'Dimitar Ruskov16', password: '123asd'},
        { email: 'dimitar.rskv+17@gmail.com', name: 'Dimitar Ruskov17', password: '123asd'},
        { email: 'dimitar.rskv+18@gmail.com', name: 'Dimitar Ruskov18', password: '123asd'},
        { email: 'dimitar.rskv+19@gmail.com', name: 'Dimitar Ruskov19', password: '123asd'}
    ];

    User.insertMany(users)
        .then(function(users) {
            res.send(users);
        })
        .catch(function(err) {
            return next(err);
        });
};

export let instagramLogin = (req: Request, res: Response, next: NextFunction) => {
    const profile = req.user.profile;
    const accessToken = req.user.accessToken;

    User.findOne({ instagram: profile.id }, (err, existingUser) => {
        if (err) { return res.send(400, 'Login Failed'); }
        if (existingUser) {
            req.user = existingUser;
            next();
        } else {
            const user: any = new User();
            user.instagram = profile.id;
            user.tokens.push({ kind: 'instagram', accessToken });
            user.profile.name = profile.displayName;
            user.profile.picture = profile.profile_picture;
            user.save((err: Error) => {
                if (err) { return res.send(400, 'Account Creation Failed'); }
                req.user = user;
                next();
            });
        }
    });
};

export let googleLogin = (req: Request, res: Response, next: NextFunction) => {
    const profile = req.user.profile;
    const accessToken = req.user.accessToken;

    User.findOne({ email: profile.email }, (err, existingUser) => {
        if (err) { return res.send(400, 'Login Failed'); }
        if (existingUser) {
            req.user = existingUser;
            next();
        }
        else {
            const user: any = new User();
            user.email = profile.email;
            user.google = profile.id;
            user.tokens.push({ kind: 'google', accessToken });
            user.profile.name = profile.name;
            user.profile.picture = profile.picture;
            user.save((err: Error) => {
                if (err) { return res.send(400, 'Account Creation Failed'); }
                req.user = user;
                next();
            });
        }
    });
};

export let facebookLogin = (req: Request, res: Response, next: NextFunction) => {
    const profile = req.user.profile;
    const accessToken = req.user.accessToken;

    User.findOne({ facebook: profile.id }, (err, existingUser) => {
        if (err) { return res.send(400, 'Login Failed'); }
        if (existingUser) {
            req.user = existingUser;
            next();
        }

        const user: any = new User();
        user.facebook = profile.id;
        user.tokens.push({ kind: 'facebook', accessToken });
        user.profile.name = `${profile.name.givenName} ${profile.name.familyName}`;
        user.profile.gender = profile.gender;
        user.profile.picture = `https://graph.facebook.com/${profile.id}/picture?type=large`;
        user.profile.location = (profile.location) ? profile.location.name : '';
        user.save((err: Error) => {
            if (err) { return res.send(400, 'Account Creation Failed'); }
            req.user = user;
            next();
        });
    });
};

export let instagramLink = (req: Request, res: Response, next: NextFunction) => {
    const profile = req.user.profile;
    const accessToken = req.user.accessToken;

    link(req, res, next, 'instagram', profile.id, accessToken);
};

export let googleLink = (req: Request, res: Response, next: NextFunction) => {
    const profile = req.user.profile;
    const accessToken = req.user.accessToken;

    link(req, res, next, 'google', profile.id, accessToken, profile.email);
};

export let facebookLink = (req: Request, res: Response, next: NextFunction) => {
    const profile = req.user.profile;
    const accessToken = req.user.accessToken;

    link(req, res, next, 'facebook', profile.id, accessToken);
};

function link(req: Request, res: Response, next: NextFunction, type: string, id: string, accessToken: string, gmail?: string) {
    const query: any = {};
    type === 'google' ? query.email = gmail : query[type] = id;
    User.findOne(query, (err, existingUser) => {
        if (err) { return res.send(400, 'Link Failed'); }
        if (existingUser) {
            return res.send(400, 'Account Already Exists');
        } else {
            User.findById(req.auth.id, (err, user: UserModel) => {
                if (type === 'google') user.email = gmail;
                (user as any)[type] = id;
                user.tokens.push({ kind: type, accessToken });
                user.save((err: Error) => {
                    if (err) { return res.send(400, 'Account Link Failed'); }
                    res.json(user);
                });
            });
        }
    });
}