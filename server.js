const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const passport = require("passport");
const cookieSession = require("cookie-session");
const { Strategy } = require("passport-google-oauth20");

require("dotenv").config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

// These are the auth options
// --callback url is when we loggen in to google and now its time that we get a response from googles servers
//   google is going to ping our endpoint we set and give us the response =>  user Data || failed to authenticate
// --Client ID is the ID that we get from google this is our App Id that google knows is this project
// --Client secret is the password for this App or URI registered to googles servers

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

//This function is going to work as a middleware for us to pass the Data that google brings us back and at the done
// "done" takes the error if any and the data we want to pass onward to the session cookie setting

const verifyCallback = (accessToken, refreshToken, profile, done) => {
  console.log("User profile => ", profile);
  done(null, profile);
};

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session from the cookie

passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Read the session from the cookie

passport.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

// App middlewares

// to protect us from leaking any information like what framework we using "Express" etc.
// when we send the responses to the client

app.use(helmet());

// to set up our cookie session name for the key of the cookie max age for the duration of it in miliseconds
// and the keys to serialize and deserialize the cookie when sending back and forth client-server

app.use(
  cookieSession({
    name: "session",
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);

// initialize the passport middleware in order to work with auth and all the configurations above

app.use(passport.initialize());

// midleware that will work with our session to serialize and desirialize the cookie data
// this uses the two function declared above

app.use(passport.session());

//middleware for the protected route '/secret'
//here we check if the user sending the request is valid and authenticated this user is set by passport js 
const checkLoggedIn = (req, res, next) => {
  const logedIn = req.isAuthenticated() && req.user;
  console.log(logedIn);
  if (!logedIn) {
    return res.status(401).json({
      error: "You must log in!",
    });
  }
  next();
};

//Routes handlers

// first when we click on log in we are going to ping this route and this is going to call the passport functionalities and redirect us to google
// the scope is what we want to get from the google response

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

// This route is the route that google is going to ping when done authenticating
// we set success and failure redirects and set the session to true so now we can serialize the 
// cookie data (client.id) that google brings us and set the cookie to the client

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("Google called us back!");
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

// server creation and initization

https
  .createServer(
    {
      cert: fs.readFileSync("cert.pem"),
      key: fs.readFileSync("key.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Server listening in port : ${PORT}`);
  });
