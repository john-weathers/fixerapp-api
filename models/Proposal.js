const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// needs to be completed...need to decide if population is necessary for proposals and bids or if the refs just need to be on the proposals and if there should be a separate bid schema

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
        required: true,
        match: /^.{1,64}@.{1,255}$/,
    },
    password: {
        type: String,
        required: true,
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
    // set up for $geoNear functionality
    defaultLocation: {
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
    activeJob: [], // look into mongoose populate function and other info on references...may be best way
    bids: [], // think about if array makes sense...think about schedule data...could somehow have separate field, may make sense to attach it here, etc.

});

module.exports = mongoose.model('Fixer', fixerSchema);