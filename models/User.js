const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const nameSchema = new Schema({
    first: {
        type: String,
        match: /^[A-Za-zÀ-ÖØ-öø-ÿ]{1,30}$/,
    },
    last: {
        type: String,
        match: /^[A-Za-zÀ-ÖØ-öø-ÿ]{1,30}$/,
    },
});

function getRating() {
    if (this.ratings.length) {
        return this.ratings.reduce((a, cv) => a + cv) / this.ratings.length;
    } else {
        return null;
    }
}

// consider adding profile photos

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        match: /^.{1,64}@.{1,255}$/,
    },
    password: {
        type: String,
        required: true,
    },
    roles: {
        user: {
            type: Number,
            default: 2505,
        },
        premiumUser: Number,
    },
    name: {
        type: nameSchema,
        required: true,
    },
    phoneNumber: {
        type: String,
        required: true,
        match: /^[\+0-9]{0,4}[-\s\.]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{2,4}[-\s\.]?[0-9]{2,4}[-\s\.]?[0-9]{2,4}$/,
    },
    // set up for $geoNear functionality
    defaultLocation: {
        type: {
            type: String,
            enum: ['Point'],
        },
        coordinates: [Number],
    },
    defaultAddress: String,
    ratings: [Number],
    rating: {
        type: Number,
        get: getRating,
    },
    refreshToken: [String],
    // requests: [{ type: Schema.Types.ObjectId, ref: 'Request' }],
    // proposals: [{ type: Schema.Types.ObjectId, ref: 'Proposal' }],
});

module.exports = mongoose.model('User', userSchema);