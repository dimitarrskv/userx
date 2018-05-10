/**
 * Module dependencies.
 */
import * as express from 'express';
import * as socketIo from 'socket.io';
import * as compression from 'compression';  // compresses requests
import * as session from 'express-session';
import * as bodyParser from 'body-parser';
import * as logger from 'morgan';
import * as errorHandler from 'errorhandler';
import * as dotenv from 'dotenv';
import * as mongo from 'connect-mongo';
import * as path from 'path';
import * as mongoose from 'mongoose';
import * as passport from 'passport';
import expressValidator = require('express-validator');


const MongoStore = mongo(session);

/**
 * Load environment variables from .env file, where API keys and passwords are configured.
 */
dotenv.config({ path: '.env.example' });


/**
 * Controllers (route handlers).
 */
import * as userController from './controllers/user';
import * as roleController from './controllers/role';
import * as apiController from './controllers/api';

/**
 * API keys and Passport configuration.
 */
import * as passportConfig from './config/passport';

/**
 * Create Express server.
 */
const app = express();

passport.use(passportConfig.local);
passport.use(passportConfig.facebook);
passport.use(passportConfig.instagram);
passport.use(passportConfig.google);
passport.use(passportConfig.linkedIn);

app.use(function (req, res, next) {
  // Website you wish to allow to connect
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:4200');

  // Request methods you wish to allow
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE');

  // Request headers you wish to allow
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Expose-Headers', 'Authorization');
  // Pass to next layer of middleware
  next();
});

/**
 * Connect to MongoDB.
 */
// mongoose.Promise = global.Promise;
mongoose.connect(process.env.MONGODB_URI || process.env.MONGOLAB_URI);

mongoose.connection.on('error', () => {
  console.log('MongoDB connection error. Please make sure MongoDB is running.');
  process.exit();
});

/**
 * Express configuration.
 */
app.set('port', process.env.PORT || 4300);

app.use(compression());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(expressValidator());

app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

/**
 * Primary app routes.
 */
app.post('/auth/login', userController.login, userController.generateToken, userController.sendToken);
app.post('/auth/facebook',
  passport.authenticate('facebook-token', {session: false}),
  userController.facebookLogin,
  userController.oAuthlogin,
  userController.generateToken,
  userController.sendToken);
app.get('/auth/google',
  passport.authenticate('google-token', {session: false}),
  userController.googleLogin,
  userController.oAuthlogin,
  userController.generateToken,
  userController.sendToken);
app.get('/auth/instagram',
  passport.authenticate('instagram-token', {session: false}),
  userController.instagramLogin,
  userController.oAuthlogin,
  userController.generateToken,
  userController.sendToken);
app.get('/auth/linked-in', passport.authenticate('linkedin-token', {session: false}), userController.oAuthlogin, userController.generateToken, userController.sendToken);
app.get('/auth/me', userController.authenticate, userController.getCurrentUser, userController.getOne);
/**
 * API examples routes.
 */
app.post('/account/profile', userController.authenticate, userController.getCurrentUser, userController.updateProfile);
app.post('/account/password', userController.authenticate, userController.getCurrentUser, userController.updatePassword);
app.post('/account/link/facebook',
  userController.authenticate,
  passport.authenticate('facebook-token', {session: false}),
  userController.facebookLink);
app.post('/account/link/google',
  userController.authenticate,
  passport.authenticate('google-token', {session: false}),
  userController.googleLink);
app.post('/account/link/instagram',
  userController.authenticate,
  passport.authenticate('instagram-token', {session: false}),
  userController.instagramLink);

/**
 * API examples routes.
 */
app.get('/user/list', userController.authenticate, userController.list);
app.get('/user/bulk', userController.bulkCreate); // TODO: Remove

app.get('/role/list', userController.authenticate, roleController.list);
app.get('/role/:id', userController.authenticate, roleController.getById);
app.post('/role/create', userController.authenticate, roleController.create);
app.post('/role/update', userController.authenticate, roleController.update);

/**
 * Error Handler. Provides full stack - remove for production
 */
app.use(errorHandler());

/**
 * Start Express server.
 */
const server = app.listen(app.get('port'), () => {
  console.log(('  App is running at http://localhost:%d in %s mode'), app.get('port'), app.get('env'));
  console.log('  Press CTRL-C to stop\n');
});

module.exports = app;