var app=require("./index");
app.set("port",process.env.PORT||3000);
var server=app.listen(app.get("port"),function(){
console.log("Server Started",server.address().port)
});