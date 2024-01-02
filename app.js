const express = require("express");

require("dotenv").config();
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "I have many secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/userDB", {
    useNewUrlParser: true,
  }); // making database

  const userSchema = new mongoose.Schema({
    // mongodb schema
    username: String,
    email: String,
    password: String,
    google_Id: String,
    facebook_Id: String,
    secret: String,
  });

  userSchema.plugin(passportLocalMongoose); //plugin
  userSchema.plugin(findOrCreate);

  const User = new mongoose.model("User", userSchema); // making the model or collection in the mongodb

  // CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
  passport.use(User.createStrategy());

  passport.serializeUser(function (user, cb) {
    // responsible to make the cookies
    process.nextTick(function () {
      return cb(null, { id: user._id });
    });
  });

  passport.deserializeUser(function (user, cb) {
    // cookies which are send with the res.redirect or with direct req is deserielize
    process.nextTick(function () {
      return cb(null, user);
    });
  });

  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets",
        profileFields: ["id", "displayName", "email"],
      },
      function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate(
          { username: profile.displayName, facebook_Id: profile.id },
          function (err, user) {
            return cb(err, user);
          }
        );
      }
    )
  );

  passport.use(
    new GoogleStrategy(
      {
        // step 2) client id clientSecret and callbackURL is send with the authencation request
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
      },
      function (accessToken, refreshToken, profile, cb) {
        // is triggered after authentication is done from the google and renponse is send to  "/auth/google/secrets" by google

        User.findOrCreate(
          { username: profile.displayName, google_Id: profile.id },
          function (err, user) {
            return cb(err, user);
          }
        );
      }
    )
  );

  app.get("/", function (req, res) {
    res.render("home.ejs");
  });

  app.get(
    "/auth/google",
    passport.authenticate(
      "google",
      {
        scope: ["profile"],
      } /* what ever information of user we want is send in scope */
    )
  ); // step 1 )  starting the authentication (req.isAuthenticated() is false) so req for authentication is send to the google

  app.get(
    "/auth/google/secrets", // response is send by google on this route after authentication

    passport.authenticate("google", { failureRedirect: "/login" }), // this is triggered after the authenticaten ,findOrCreate callback is trigger from the Google stratgy and after that serilization is done with it
    function (req, res) {
      // Successful authentication, redirect response
      // also sending cookies with the redirect response
      res.redirect("/secrets"); //
    }
  );

  app.get("/login", function (req, res) {
    res.render("login.ejs");
  });

  app.get("/register", function (req, res) {
    res.render("register.ejs");
  });

  app.get("/secrets", async function (req, res) {
    if (req.isAuthenticated()) {
      const myuser = await User.find({ secret: { $ne: null } }); // return array

      res.render("secrets.ejs", { Myuser: myuser });
    } else {
      res.redirect("/login");
    }
  });

  app.post("/register", async function (req, res) {
    User.register(
      { username: req.body.username },
      req.body.password,
      async function (err, user) {
        if (err) {
          console.log(err);
          res.render("/register");
        } else {
          await passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

  app.post(
    "/login",
    passport.authenticate("local", {
      failureRedirect: "/login",
      failureMessage: true,
    }), // serialization is do after the authentication and findorCreate
    function (req, res) {
      res.redirect("/secrets"); // cookies is send with the respose after the serialization
    }
  );

  app.get("/auth/facebook", passport.authenticate("facebook"));

  app.get(
    "/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function (req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
    }
  );

  app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
      res.render("submit.ejs");
    } else {
      res.redirect("/login");
    }
  });

  app.post("/submit", async function (req, res) {
    const submitted = req.body.secret;

    if (req.isAuthenticated()) {
      console.log(req.user.id);
      const myuser = await User.findOne({ _id: req.user.id });
      myuser.secret = submitted;
      myuser.save();
      res.redirect("/secrets");
    } else {
      res.redirect("/login");
    }
  });

  app.get("/logout", function (req, res) {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });

  app.listen(3000, function () {
    console.log("server is activated at the port number 3000");
  });
}
