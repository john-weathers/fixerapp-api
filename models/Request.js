const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// look into transforming populated documents, if needed

// a more robust matching system (in terms of matching appropriately skilled technicians) would require some type of categorization
// as well as perhaps notes/images of the issue in need of repair

const requestSchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    userAddress: String,
    userLocation: {
        type: {
            type: String,
            enum: ['Point'],
        },
        coordinates: [Number],
        required: true,
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
      enum: ['en route', 'arriving', 'estimating', 'fixing', 'complete' ],
    },
    route: {
      coordinates: [[Number]],
      instructions: [String],
      duration: Number,
      lastUpdatedAt: Date,
    },
    estimate: Number, 
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

module.exports = mongoose.model('Request', requestSchema);