const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');

require('dotenv').config()

const PORT = 3000;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
};

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
}

const verifyCallback = (accessToken, refreshToken, profile, done) => {
    console.log('User profile => ', profile);
    done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

const app = express();

app.use(helmet())

app.use(passport.initialize());

const checkLoggedIn = (req, res, next) => {
    const logedIn = true; //TODO
    if(!logedIn){
        return res.status(401).json({
            error: "You must log in!"
        })
    }
    next();
};


app.get("/auth/google",
    passport.authenticate('google', {
        scope: ['email']
    })
);

app.get("/auth/google/callback", 
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: false
    }),
    (req, res) => {
        console.log('Google called us back!');
    }
);

app.get("/auth/logout", (req, res) => {});

app.get("/", (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Your secret value id 22!");
});

app.get("/failure", (req, res) => {
  return res.send("Failed to log in!");
});

https.createServer({
    cert: fs.readFileSync('cert.pem'),
    key : fs.readFileSync('key.pem')
}, app).listen(PORT, () => {
  console.log(`Server listening in port : ${PORT}`);
});
