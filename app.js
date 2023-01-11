//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const passport = require("passport");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook");


const app = express();


mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']} );



const USER = mongoose.model("user", userSchema);

passport.use(USER.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  USER.findById(id, function(err, user) {
    done(err, user);
  });
});


app.use(express.static("public"));
app.use(bodyParser.urlencoded({
  extended: true
}));
app.set('view engine', "ejs");
app.use(session({
  secret: "our little secret",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

//FacebookStrategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    USER.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//GoogleStrategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    USER.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

//FacebookAuth
app.get('/auth/facebook',
  passport.authenticate('facebook')
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  }
);


//GoogleAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile']}));

app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.post("/login", function(req, res) {

  // const email = req.body.username;
  // const password = req.body.password;
  //
  // USER.findOne({
  //   email: email
  // }, function(err, foundUser) {
  //   if (foundUser) {
  //     bcrypt.compare(password, foundUser.password, function(err, result) {
  //       if(result == true) res.render("secrets");
  //     });
  //   } else res.send("no user");
  // });

  const user = new USER({
    username: req.body.username,
    password: req.body.password
  })

  req.login(user, function(err) {
    if (err) console.log(err);
    else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      })
    }
  })
});

app.get("/logout", function(req, res) {
  req.logout(function(err) {
    if (err) console.log(err);
    else res.redirect("/login");
  });

});

app.get("/register", function(req, res) {
  res.render("register");
});

app.post("/register", (req, res) => {
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //     const newUser = new USER({
  //       email: req.body.username,
  //       password: hash
  //     });
  //
  //     newUser.save();
  //     res.send("successfully registered");
  //   });

  USER.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) console.log(err);
    else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      })
    }
  })
});


app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else res.redirect("/login");
})

// app.get("/secrets", function(req, res) {
//   res.render("secrets");
// });

app.get("/submit", function(req, res) {
  res.render("submit");
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  //user here is from passport which it automatically saved for us
  USER.findById(req.user.id, function(err, foundUser){
    if(err) console.log(err);
    else{
      if(foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save();
        // console.log("successuflly submit");
      }
    }
  })
})

app.listen(3000, () => {
  console.log("app is running on port 3000");
});
