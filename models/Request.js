const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// figure out requestStatus validation...need to read up on pre save hooks because validators on update seem to not behave ideally for my purposes
// want to make sure the updated request status is not the same as the pre-updated request status (i.e., if it's the same, it would be a stale status)

// pre save notes: something like requestSchema.pre('updateOne', { document: true, query: false })
// sounds like not specifying those options will mean the incorrect this being passed to callback functions?

// note: populated documents can be transformed and there are autopopulate pre save hooks/a plugin if desired

const requestSchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true }, // can populate specific fields here...(email, name, phoneNumber...possibly relevant-roles, rating)
    // set up for $geoNear functionality
    location: {
        type: {
            type: String,
            enum: ['Point'],
        },
        coordinates: [Number],
        required: true,
    },
    requestStatus: {
      type: String,
      enum: ['active', 'pending', 'fulfilled', 'failed', 'cancelled'],
      required: true,
      validate: {
        validator: function(v) {
          if (this?.options?.previous === v) return false;
          return true;
        },
        message: () => `Request status must be different from previous value`
      },
    },
    requestedAt: {
      type: Date,
      required: true,
      default: new Date(),
    },
    fixer: { type: Schema.Types.ObjectId, ref: 'Fixer' }, // can populate specific fields here...(name, phoneNumber, currentLocation, rating?)
});

module.exports = mongoose.model('Request', requestSchema);