const mongoose = require('mongoose');
require('dotenv').config();

async function main(){
    try{
        await mongoose.connect(process.env.DB_CONNECT_KEY);
        console.log('Database connection successful');
    }
    catch(err){
        console.error('Database connection failed:', err.message);
        throw err;
    }
}

module.exports = main;