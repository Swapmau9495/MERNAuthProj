const mongoose =require('mongoose')
const mongo_url = process.env.MONGO_CONN;
mongoose.connect(mongo_url)
 .then(()=>{
    console.log("MomgoBD connected Successfully")

 })
 .catch((err)=>{
    console.log("MomgoBD connection error",err)
 })