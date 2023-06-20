const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const requestSchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    userAddress: String,
    userLocation: {
      type: {
          type: String,
          enum: ['Point'],
      },
      coordinates: [Number],
    },
    fixerLocation: {
      type: {
        type: String,
        enum: ['Point'],
      },
      coordinates: [Number],
    },
    active: {
      type: Boolean,
      required: true,
      validate: {
        validator: function(v) {
          if (this?.options?.previous === v) return false;
          return true;
        },
        message: () => 'Active status already set to {VALUE}'
      }
    },
    currentStatus: {
      type: String,
      enum: ['in progress', 'fulfilled', 'failed', 'cancelled'],
      /*validate: {
        validator: function(v) {
          if (this?.options?.previous === v) return false;
          return true;
        },
        message: () => `Request status must be different from previous value`
      },*/
    },
    trackerStage: {
      type: String,
      enum: ['en route', 'arriving', 'fixing', 'complete' ],
    },
    route: {
      coordinates: [[Number]],
      instructions: [String],
      duration: Number,
      lastUpdatedAt: Date, // remove?
    },
    eta: Date,
    notes: String,
    quote: {
      amount: Number,
      details: [String],
      pending: Boolean,
      revisedPending: Boolean,
      revisedAccepted: Boolean,
    },
    requestedAt: {
      type: Date,
      required: true,
      default: new Date(),
    },
    assignedAt: Date,
    workStartedAt: Date,
    fulfilledAt: Date,
    fixer: { type: Schema.Types.ObjectId, ref: 'Fixer' }, // can populate specific fields here...(name, phoneNumber, currentLocation, rating?)
});

requestSchema.index({ userLocation: '2dsphere' });

module.exports = mongoose.model('Request', requestSchema);