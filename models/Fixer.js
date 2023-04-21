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
    rating: Number,
    refreshToken: [String],
    prevTokens: {
        refreshTokens: [String],
        lastRefresh: Date,
        accessToken: String,
    },
    activeJob: { type: Schema.Types.ObjectId, ref: 'Request' },
    // bids: [{ type: Schema.Types.ObjectId, ref: 'Bid' }], think about schedule data as well...might make most sense to use bid

});

module.exports = mongoose.model('Fixer', fixerSchema);