const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const resumeTokenSchema = new Schema({
    collectionName: String,
    token: String,
});

module.exports = mongoose.model('ResumeToken', resumeTokenSchema);