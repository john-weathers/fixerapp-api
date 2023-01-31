const mongoose = require('mongoose');
const Schema = mongoose.Schema;

function getRating() {
    if (this.ratings.length) {
        return this.ratings.reduce((a, cv) => a + cv) / this.ratings.length;
    } else {
        return null;
    }
}

const fixerSchema = new Schema({
    email: {
        type: String,
        require: true,
        match: /^.{1,64}@.{1,255}$/,
    },
    password: {
        type: String,
        required: true,
        match: /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$/,
    },
    roles: {
        fixer: {
            type: Number,
            default: 3450,
        },
        premiumFixer: Number,
    },
    name: {
        first: {
            type: String,
            required: true,
            match: /^[A-Za-zÀ-ÖØ-öø-ÿ]{1,30}$/,
        },
        last: {
            type: String,
            required: true,
            match: /^[A-Za-zÀ-ÖØ-öø-ÿ]{1,30}$/,
        },
    },
    phoneNumber: {
        type: String,
        required: true,
        match: /^[\+0-9]{0,4}[-\s\.]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{2,4}[-\s\.]?[0-9]{2,4}[-\s\.]?[0-9]{2,4}$/,
    },
    lookingForWork: {
        type: Boolean,
        default: false,
    },
    // set up for $geoNear functionality
    location: {
        type: {
            type: String,
            enum: ['Point'],
        },
        coordinates: [Number],
    },
    destination: {
        type: {
            type: String,
            enum: ['Point'],
        },
        coordinates: [Number],
    },
    ratings: [Number],
    rating: {
        type: Number,
        get: getRating,
    },
    refreshToken: [String],
    currentMatch: {
        email: String,
        name: {
            first: String,
            last: String,
        },
    },
});

module.exports = mongoose.model('Fixer', fixerSchema);