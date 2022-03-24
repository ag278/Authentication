//jshint esversion:6
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser')
const ejs = require('ejs');
//const encrypt = require('mongoose-encryption')
//const md5 = require('md5');  //for hashing
// const bcrypt = require('bcrypt'); //for salting and hashing password with brcypt
// const saltRounds = 10;
const session = require('express-session')
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const app = express();

//initialising middleware
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

//initialising session
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}))

//initialising passport
app.use(passport.initialize());

//initialising passport to deal with the session
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB', { useNewUrlParser: true });


const userSchema = new mongoose.Schema({
    email: String,
    password: String
})
//for mongoose- encryption
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.get('/', (req, res) => {
    res.render('home')
})


app.get('/login', (req, res) => {
    res.render('login')
})

app.get('/register', (req, res) => {
    res.render('register')
})

app.get('/secrets', (req, res) => {

    //if the user is still authenticated( means its cookie is still there and its session is not expired(it has not closed the browser), then it will render the secrets) else we have to login again
    if (req.isAuthenticated()) {
        res.render('Secrets');

    }
    else {
        res.redirect('/login');
    }
})
app.post('/register', (req, res) => {

    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect('/register');
        }
        else {
            //authenticating the user
            passport.authenticate('local')(req, res, () => {
                //if the user is correct then we will transfer them to the secret route and send the corresponding cookie as well
                res.redirect('/secrets')
            })
        }
    })
})

app.post("/login", function (req, res) {
    //check the DB to see if the username that was used to login exists in the DB
    User.findOne({ username: req.body.username }, function (err, foundUser) {
        //if username is found in the database, create an object called "user" that will store the username and password
        //that was used to login
        if (foundUser) {
            const user = new User({
                username: req.body.username,
                password: req.body.password
            });
            //use the "user" object that was just created to check against the username and password in the database
            //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
            //return the user found in the database
            passport.authenticate("local", function (err, user) {
                if (err) {
                    console.log(err);
                } else {
                    //this is the "user" returned from the passport.authenticate callback, which will be either
                    //a false boolean value if no it didn't match the username and password or
                    //a the user that was found, which would make it a truthy statement
                    if (user) {
                        //if true, then log the user in, else redirect to login page
                        req.login(user, function (err) {
                            res.redirect("/secrets");
                        });
                    } else {
                        res.redirect("/login");
                    }
                }
            })(req, res);
            //if no username is found at all, redirect to login page.
        } else {
            //user does not exists
            res.redirect("/login")
        }
    });
});

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
})

app.listen(3000, () => {
    console.log("on port 3000");
})