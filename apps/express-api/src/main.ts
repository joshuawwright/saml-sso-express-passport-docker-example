import express from 'express';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import { Strategy, VerifyWithoutRequest } from '@node-saml/passport-saml';
import { readFileSync } from 'fs';

const samlStrategy = new Strategy({
    callbackUrl: 'http://localhost:4300/login/callback',
    entryPoint: 'http://localhost:8080/simplesaml/saml2/idp/SSOService.php',
    issuer: 'saml-poc',
    decryptionPvk: readFileSync(`./certs/key.pem`, 'utf8'),
    privateKey: readFileSync(`./certs/key.pem`, 'utf8'),
    cert: readFileSync(`./certs/idp.pem`, 'utf8')
  },
  ((profile, done) => done(null, profile)) as VerifyWithoutRequest,
  ((profile, done) => done(null, profile)) as VerifyWithoutRequest
);

passport.serializeUser(function(user, done) {
  console.log(`serialize user`, user);
  done(null, user);
});
passport.deserializeUser((user, done) => done(null, user));
passport.use('samlStrategy', samlStrategy);

const app = express();

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize({}));

const host = 'localhost';
const port = 4300;
app.listen(4300, 'localhost', () => console.log(`[ ready ] http://${host}:${port}`));

app.get('/login', passport.authenticate('samlStrategy'));

app.post('/login/callback',
  passport.authenticate('samlStrategy'),
  (req, res) => res.send(`Login Successful`)
);

app.route('/metadata').get(function(req, res) {
  res.type('application/xml');
  res.status(200);
  res.send(
    samlStrategy.generateServiceProviderMetadata(
      readFileSync('./certs/cert.pem', 'utf8'),
      readFileSync('./certs/cert.pem', 'utf8')
    )
  );
});
