require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session")
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const bcrypt = require('bcrypt');
const { authenticate } = require("passport");

const saltRounds = 10;

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized : false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/taskDB",  { useNewUrlParser: true , useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);
const userSchema = new mongoose.Schema ({
    email: {
        type:String,
        required : true
    },
    password : {
        type: String,
        required: true
    }
});
userSchema.plugin(passportLocalMongoose,{usernameField : "email"});

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/",(req,res)=>{
    res.render("landing");
});

app.get("/login",(req,res)=>{
            res.render("login");
});
app.get('/logout', (req, res) => {
    req.logout();
    req.session = null;
    res.redirect('/')
  })


app.get("/signup",(req,res)=>{
    res.render("signup");
});

app.get("/home",(req,res)=> {
    if(req.isAuthenticated){
        res.render("home");
    }
    else {

    res.redirect("/login");
    }
});
app.get('/session/destroy', function(req, res) {
    req.session.destroy();
    res.status(200).send('ok');
});

app.post("/signup",(req,res) => {
    bcrypt.genSalt(saltRounds, function (err, salt) {
        if (err) {
          console.log(err);
        } else {
            bcrypt.hash(req.body.password, saltRounds, function(err, hashedPassword) {
                User.findOne({email : req.body.email},(err,user)=>{
                    if(err){
                        console.log(err);
                        res.redirect("/");
                    }
                    else if(user) {
                        console.log("user already exists!");
                        console.log(user)
                        res.redirect("/login");
                    }
                    else {
                        const newUser = new User({
                            email : req.body.email,
                            password : hashedPassword
                        });
                        newUser.save((err)=>{
                            if(err){
                                console.log(err)
                            }
                            else {
                                res.redirect("/home")
                            }
                        });
        
                    }
                })
            })
        }
      })
       
    });

    app.post("/login",(req,res)=>{
        User.findOne({ email: req.body.email }, function(err, user) {
            if (err) 
            { console.log(err); 
            }
            if (!user) {
              console.log("Incorrect Email!")
              res.redirect("/login")
            }
            else {
                bcrypt.compare(req.body.password,user.password ,function(error, result) {
                    if (err) {
                        console.log(error)
                      } else if (!result) {
                        console.log("Password doesn't match!")
                        res.redirect("/login")
                      } else {
                        console.log("Password matches!");
                        res.redirect("/home")
                      }
                });
            }
          });
    })
    
app.listen(3000, function(){
    console.log("Server is listening on port 3000!");
});