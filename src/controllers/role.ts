import * as async from 'async';
import { default as Role, RoleModel } from '../models/Role';
import { Request, Response, NextFunction } from 'express';
import { LocalStrategyInfo } from 'passport-local';
import { WriteError } from 'mongodb';
const request = require('express-validator');
const paginate = require('express-paginate');

export let create = (req: Request, res: Response, next: NextFunction) => {
    req.assert('name', 'Please enter a name').notEmpty();

    const errors = req.validationErrors();

    if (errors)
        return res.send(400, 'Invalid Request');

    const role: any = new Role();
    role.name = req.body.name;
    role.description = req.body.description || '';
    role.permissions = req.body.permissions;
    role.save((err: Error) => {
        if (err) { return res.send(400, 'Role Creation Failed'); }
        res.json(role);
    });
};

export let update = (req: Request, res: Response, next: NextFunction) => {
    req.assert('name', 'Please enter a name').notEmpty();

    const errors = req.validationErrors();

    if (errors)
        return res.send(400, 'Invalid Request');

        Role.findById(req.body.id, (err, role: RoleModel) => {
        if (err) { return next(err); }
        role.name = req.body.name || '';
        role.description = req.body.description || '';
        role.save((err: WriteError) => {
            if (err) {
                if (err.code === 11000) {
                    res.send(400, 'A role with that name already exists.');
                }
                return next(err);
            }
            res.json(role);
        });
    });
};

export let list = (req: Request, res: Response, next: NextFunction) => {

    const limit = parseInt(req.query.limit);
    const skip = (parseInt(req.query.page) - 1) * limit;
    const filter = req.query.filter ? {
        $or: [
            { name: {$regex : '^' + req.query.filter } }]
    } : {};
    return Promise.all([
        Role.find(filter).limit(limit).skip(skip).lean().exec(),
        Role.count(filter)
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

export let getById = (req: Request, res: Response, next: NextFunction) => {

    const errors = req.validationErrors();

    if (errors)
        return res.send(400, 'Invalid Request');

    Role.findById(req.params.id, (err, role: RoleModel) => {
        if (err) { return next(err); }
        res.json(role);
    });
};
