//jshint esversion:6
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser')
const ejs = require('ejs');
//const encrypt = require('mongoose-encryption')
//const md5 = require('md5');  //for hashing
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/userDB', { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String
})
//for mongoose- encryption
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

const User = mongoose.model('User', userSchema);

app.get('/', (req, res) => {
    res.render('home')
})


app.get('/login', (req, res) => {
    res.render('login')
})
// ...
//another 
app.get('/register', (req, res) => {
    res.render('register')
})

app.post('/register', (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        const newUser = new User({
            email: req.body.username,
            password: hash
        })

        newUser.save()
            .then(res.render('secrets'))
            .catch((err) => {
                console.log(err);
            })
    });

})

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username }, (err, foundUser) => {
        if (err) console.log(err);
        else {
            if (foundUser) {
                bcrypt.compare(password, foundUser.password, function (err, result) {
                    if (result == true) {
                        res.render('secrets');
                    }
                });


            }
        }
    })
})

app.listen(3000, () => {
    console.log("on port 3000");
})