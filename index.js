// app.js
/******************** Basic Express Stuff ***************/
var express      = require('express');
var logger       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var path=require("path");
var BearerStrategy = require('passport-http-bearer').Strategy;
/*********************************************************/

/******************** Express Session ********************/
var expressSession = require('express-session');
/*********************************************************/

/******************** Configure Mongo(ose) ***************/
var dbConfig = require('./db.js');
var mongoose = require('mongoose');
var MongoStore=require("connect-mongo")(expressSession);
mongoose.connect(dbConfig.url);
/*********************************************************/

/******************** Load User Schema *******************/
var User = require('./user.js').User;
var Token=require('./user.js').Token;
var hash = require('bcryptjs');
var Secret = require('./secret.js');
/*********************************************************/

/******************** Configure Passport *****************/
var passport = require('passport');
var localStrategy = require('passport-local' ).Strategy;
var testUser=new Secret({
		name:"secret",
		secret:"Golam"
		
	});
	testUser.save(function(){
		console.log("saved");
	});
// define default 'local' strategy, used for login
passport.use(new localStrategy(
  // no strategy name (defaults to 'local'), no options, just the verify function
  function(username, password, authCheckDone) {
	 
    User.findOne({ username: username }, function(err, user) {
      if (err) {
		 
		  return authCheckDone(err);
	  }
      if (!user) 
		  return authCheckDone(null, false, 'No such user');
      if (!hash.compareSync(password, user.password)) {
        authCheckDone(null, false, 'Invalid Login');
      }
      authCheckDone(null, user);
    });
  })
);

// define 'signup' strategy, used for login
passport.use('signup', new localStrategy({
    // need req in callback to get post params
    passReqToCallback : true
  },
  // the 'verify' function for this 'signup' strategy
  function(req, password, username, authCheckDone) {
	 
    User.findOne({username: req.body.username}, function(err, user) {
      if (err) return authCheckDone(err);
      if (user) {
        return authCheckDone(null,
          false,
          'User ' + req.body.username + ' already exists.');
      }
      // it's safe, now create the user account
      var user = {
		  
        username: req.body.username || 'johndoe',
        password: hash.hashSync( req.body.password || 'always42',
                                 hash.genSaltSync(1)),
        name: req.body.name || 'John Doe',
        email: req.body.email || 'jd@yahoo.com'
      };
      new User(user ).save( function(err, user) {
        if (err) return authCheckDone(err);
        if (!user) return authCheckDone('Failed on create user :(');
        authCheckDone(null, user);
      });

    });
  })
);

/*passport.use("secret",new localStrategy(function(cb){
	var testUser=new Secret({
		name:"secret",
		secret:"Golam"
	});
cb(null,testUser);
})
);
*/
/*User.methods.generateToken=function(){
	var token=new Token();
	token.value="test value";
	token.user=this._id;
	this.token=token._id;
	this.save(function(err){
		if(err){
			throw err;
		}
		token.save(function(err){
			if(err){
				throw err;
			}
			
		});
	});
	
}*/

passport.use(new BearerStrategy({},
		function(token, done){
			Token.findOne({value: token}).populate('user').exec(function(err, token){
				//console.log(token);
				if(!token)
					return done(null, false);
				return done(null, token.user);
			})
		}));








// define the auth verification middleware
function verifyAuth(req,res,next) {
  if ( !req.isAuthenticated() ) {
    return res.json(401, {
      err: 'Please login if you want my secret!',
      sessionId: req.session.id
    });
  }
  next();
}
/*function mySecret(req,res,next){
	var testUser=new Secret({
		name:"secret",
		secret:"Golam"
		
	});
	testUser.save(function(){
		console.log("saved");
	});
	next();
}
*/



passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
   User.findById(id, function (err, user) {
	   done(err,user);
  });
});

/*********************************************************/

/*************** Create Express Server *******************/
var app = express();
/*********************************************************/

/************ Configure Express Middleware ***************/
app.use(express.static(path.join(__dirname,"/")));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: false
}));
app.use(logger('dev'));
/*********************************************************/

/******************* Configure  Session ******************/
app.use(expressSession({
	secret: 'thisIsTopSecretSoDontTellAnyone',
	cookie: {
    path: '/',
    httpOnly: true,
    secure: false
  },
  resave:true,
  saveUninitialized:true,
  store:new MongoStore({mongooseConnection:mongoose.connection}) //session not expire after server down
}));
/*****ret: 'thisIsTopSecretSoDontTellAnyone',
  ****************************************************/

/******************* Configure Passport ******************/
app.use(passport.initialize());
app.use(passport.session());
/*********************************************************/

/******************* Test Middleware ******************/
app.use(function(req,res,next){
  console.log('Request Object:');
  console.log('Session ID:', req.session.id);
  next();
});
/*********************************************************/

/******************** Configure Routes ******************/
// Hello World server is fuzzy wuzzy
app.get('/', function(req,res) {
  res.send(200, {
    msg: 'Hello World',
    sessionId: req.session.id
  });
});

// route to create an account
app.post('/users', function(req,res,next) {
  passport.authenticate('signup', function(err, user, info) {
    if (err) {
      return res.json(500, {
        err:err,
        sessionId: req.session.id
      });
    }
    if (!user) {
      return res.json( 400,
        {
        err: info,
        sessionId: req.session.id
        });
    }
    req.login(user,  function(err) {
      if (err) {
        return res.json( {
          err: 'Could not login user',
          sessionId: req.session.id
        });
      }
      res.json(201, {
        user: user,
        sessionId: req.session.id
      });
    });
  })(req, res, next);
});

// Login route - note the use 'info' to get back error condition from passport
app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
	  console.log("1st");
    if (err) { 
	return next(err) ;
	}
    if (!user) {
      return res.json(401, {
        err: info,
        sessionId: req.session.id
      });
    }
    req.logIn(user, function(err) {
		console.log("2nd");
      if (err) {
        return res.json(500, {
          err: 'Could not log user in',
          sessionId: req.session.id
        });
      }
      res.json(200, {
        msg: 'Login success!!',
        sessionId: req.session.id
      });
    });
  })(req, res, next);
 
});

// logout - destroys the session id, removes req.user
app.get('/logout', function(req, res) {
  req.logout();
  res.json(200, {
    msg: 'Bye!'
  });
});

// Route to read the secret protected by auth
app.get('/secret', verifyAuth, function(req, res){
  //passport.authenticate("secret");
  //mySecret();
  // gate is open! proceed to read the secret
  Secret.findOne({name:"secret"}, function(err, secret) {
    if (err) {
      return res.json(500, {
        err: 'Could not access secret in dB :('
      });
    }
    res.json(200, {
      secret: secret.secret,
      sessionId: req.session.id
    });
  });
});
app.get("/getToken",function(req,res){
	User.findOne({_id:req.user._id}).populate("token").exec(function(err,user){
		
		if(user.token==null){
			
			user.generateToken();
			res.redirect("/testToken");
		}
		else{
			res.redirect("/testToken");
		}
		
	});
	
	
});
app.get("/testToken",function(req,res){
	
	User.findOne({_id:req.user._id}).populate("token").exec(function(err,user){
		//res.json(user);
		res.redirect("/auth?access_token=" + user.token.value);
	});
	
});

app.get("/auth",passport.authenticate("bearer",	{session:false}),function(req,res){
	res.send(req.user);
});

app.get("/information",function(req,res){
	res.sendFile("./form.html");
});


/*********************************************************/

/***************** Configure Error Handlers  *************/
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

app.use(function(err, req, res) {
	console.log("occurred");
  res.status(err.status || 500);
  res.end(JSON.stringify({
    message: err.message,
    error: {}
}));
});
/*********************************************************/

/****************** Export Server Module  *****************/
// passport-demo.js will import this module, and we start the server there
module.exports = app;