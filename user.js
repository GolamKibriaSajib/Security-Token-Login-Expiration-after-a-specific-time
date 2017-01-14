var mongoose=require("mongoose");
var randomToken = require('random-token');
var Schema=mongoose.Schema;
var UserSchema=mongoose.Schema({
username:String,
password:String,
name:String,
email:String,
token:{
	type:Schema.Types.ObjectId,
	ref:"Token",
	default:null
	
}	
});

var tokenSchema=mongoose.Schema({
value:String,
	user:{
		type:Schema.Types.ObjectId,
		ref:"User"
	},
		expireAt:{
			type:Date,
			expires:60, //token expire time i set it 1 min
			default:Date.now
		}
	});

UserSchema.methods.generateToken=function(){
	var token=new Token();
	token.value=randomToken(32);
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
	
}


var User=mongoose.model("User",UserSchema);
var Token=mongoose.model("Token",tokenSchema);
Models={User:User,Token:Token};
module.exports=Models;