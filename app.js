

import dotenv from "dotenv";
dotenv.config();
import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";
import findOrCreate from "mongoose-findorcreate";
import Google from 'passport-google-oauth20';
import Facebook from 'passport-facebook';

const GoogleStrategy = Google.Strategy;
const FacebookStrategy = Facebook.Strategy;


const app = express();


app.set('view engine','ejs');
app.use(express.urlencoded({extended: true}));
app.use(express.static("public"));







app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());







mongoose.connect(process.env.SECRETS_DB);
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("secretUser",userSchema);










passport.use(User.createStrategy());







passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, (err, user)=> {
      return cb(err, user);
    });
  }
));




passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, (err, user)=> {
      return cb(err, user);
    });
  }
));








passport.serializeUser((user, done) =>{
    done(null, user.id);
  });
passport.deserializeUser((id, done) =>{
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });




  
  
  





// all get requests

app.get("/", (req, res)=>{
  res.render("home");
});

app.get('/auth/google', passport.authenticate('google', { scope: ["profile"] }));

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      res.redirect('/secrets');
});

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get("/register", (req, res)=>{
  res.render("register");
});

app.get("/login", (req, res)=>{
  res.render("login");
});

app.get("/secrets", (req, res)=>{
  if(req.isAuthenticated()){
    User.find({"secret": {$ne: null}}, (err, foundUsers)=>{
        if(err){
            console.log(err);
        }else{
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    })
  }else{
    res.redirect("/login");
  }
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
  

app.get("/logout", (req, res)=>{
  req.logout();
  res.redirect("/");
});





// all post requests 

app.post("/register",(req, res)=>{
  User.register( {username: req.body.username} , req.body.password , (err)=>{  
      if(err){
          console.log(err);
          res.redirect("/register");
      }else{
          passport.authenticate("local")(req, res, ()=>{
              res.redirect("/secrets");
          });
      }
  });
});



app.post("/login",(req, res)=>{
  const newUser = new User({
      username: req.body.username,
      password: req.body.password
  });

  req.login(newUser, (err)=>{
      if(err){
          console.log(err);
          res.redirect("/login");
      }else{
          passport.authenticate("local")(req, res, ()=> {
            res.redirect("/secrets")});
      }
  });
});



app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});




// Error Handler
app.use((err, req, res, next)=>{
  if(err){
    if(err.code===11000){
    }
    res.redirect("/register");
  }
});






app.listen(process.env.PORT || 3000, ()=>{
    console.log("Server is running on port 3000");
});




/*
    Authentication & Security levels

    level 1 -- Taken email and password of user to let them see the secret page.
    problem -- very easy to hack because of storing plaintext into our db.

    level 2 -- Encrypted our password data with mongoose encrypt package.
               secret variable removed from main stream and added into environment variable.
    problem -- Has a secret key with which the password was accessible.

    level 3 -- Used md5 hashing function to convert user's password into irreversible hashcode.
    problem -- It will always generate same hashcode for a particular plain text,
               which can be hacked by hashmap or dictionary and phone directory method.

    level 4 -- Encrypted our password with hash function bcrypt with 10 times salt.
               Salting is a process of adding a plain text with actual password and
               passing it through hash function for specific times.

    level 5 -- Authentication by passportjs using local stratagies(by username & password)
               creating sessions & cookies (starts when login and ends when browser closed)





    https://expressjs.com/en/4x/api.html
    https://www.npmjs.com/package/express-session
    http://www.passportjs.org/docs/
    http://www.passportjs.org/packages/passport-local/
    https://www.npmjs.com/package/passport-local-mongoose


    

    

    plugins        -- a software that adds an additional feature in your app.
    middlware      -- a software that works in between the actual workflow i.e between client-server on each request.
    local-     
    authentication -- authentication done by username and password.


    website: https://fast-wildwood-74186.herokuapp.com/

*/