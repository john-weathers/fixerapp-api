const mongoose = require('mongoose');
const { logEvents } = require('../middleware/logEvents');

const connectDb = async () => {
    try {
        await mongoose.connect(process.env.DATABASE_URI, {
            useUnifiedTopology: true,
            useNewUrlParser: true,
        })
    } catch (err) {
        logEvents(`${err.name}\t${err.message}\tCould not connect to database`, 'reqLog.txt');
        console.log(`${err.name}: ${err.message}`);
    }
}

module.exports = connectDb;