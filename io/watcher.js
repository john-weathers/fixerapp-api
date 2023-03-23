const Request = require('../models/Request');
const { errListener } = require('./watcherHelpers');

const watcher = async (userNsp, fixerNsp, resumeToken) => {
  // I think best here will be operationType: update && (updated currentStatus || updated trackerStage || updated location)
  // operationType: 'update',
  // 'updateDescription.updatedFields.currentStatus': { $exists: true }, 
  //
  let changeStream;
  const pipeline = [
    {
      $match: {
        $and: [
          { operationType: 'update' },
          { $or: [
            { 'updateDescription.updatedFields.currentStatus': { $exists: true } },
            { 'updateDescription.updatedFields.trackerStage': { $exists: true } },
            { 'updateDescription.updatedFields.fixerLocation': { $exists: true } }
          ] }
        ]
      }
    }
  ];
  const err = {
    state: false,
  }

  // make sure a change stream is continuously open (but not more than one for any significant amount of time) and properly resumed if applicable
  if (!resumeToken) {
    changeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
      resumeToken = change._id;
      console.log(change);
      const fullDocument = change.fullDocument;
      userNsp.to(String(fullDocument._id)).emit('job update', {
        currentStatus: fullDocument.currentStatus,
        fixerLocation: fullDocument.fixerLocation.coordinates,
        trackerStage: fullDocument.trackerStage,
        estimate: fullDocument?.estimate,
      });
      if (change.updateDescription.updatedFields?.currentStatus || change.updateDescription.updatedFields?.trackerStage) {
        fixerNsp.to(String(fullDocument._id)).emit('job update', {
          currentStatus: fullDocument.currentStatus,
          trackerStage: fullDocument.trackerStage,
          estimate: fullDocument?.estimate,
        });
      }
      
    });
  } else {
    let streamResponse = false;
    changeStream = Request.watch(pipeline, { fullDocument: 'updateLookup', resumeAfter: resumeToken }).on('change', change => {
      if (change) {
        streamResponse = true;
      }
      resumeToken = change._id;
      console.log(change);
      const fullDocument = change.fullDocument;
      userNsp.to(String(fullDocument._id)).emit('job update', { // this object can likely be reduced
        currentStatus: fullDocument.currentStatus,
        fixerLocation: fullDocument.fixerLocation.coordinates,
        trackerStage: fullDocument.trackerStage,
        estimate: fullDocument?.estimate,
      });
      if (change.updateDescription.updatedFields?.currentStatus || change.updateDescription.updatedFields?.trackerStage) {
        fixerNsp.to(String(fullDocument._id)).emit('job update', {
          currentStatus: fullDocument.currentStatus,
          trackerStage: fullDocument.trackerStage,
          estimate: fullDocument?.estimate,
        });
      }
    })

    setTimeout(() => {
      if (!streamResponse && !err.state) {
        changeStream.off('error', () => console.log('error listener removed'));
        changeStream.close()
        const newChangeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
          resumeToken = change._id;
          console.log(change);
          const fullDocument = change.fullDocument;
          userNsp.to(String(fullDocument._id)).emit('job update', { // this object can likely be reduced
            currentStatus: fullDocument.currentStatus,
            fixerLocation: fullDocument.fixerLocation.coordinates,
            trackerStage: fullDocument.trackerStage,
            estimate: fullDocument?.estimate,
          });
          if (change.updateDescription.updatedFields?.currentStatus || change.updateDescription.updatedFields?.trackerStage) {
            fixerNsp.to(String(fullDocument._id)).emit('job update', {
              currentStatus: fullDocument.currentStatus,
              trackerStage: fullDocument.trackerStage,
              estimate: fullDocument?.estimate,
            });
          }
        })
        // handle error events
        errListener(userNsp, fixerNsp, newChangeStream, resumeToken);
      }
    }, 10000) // NOTE: be aware that time may need to change or coming up with another way of validating the resume token may be needed
    // there are no ways that I have found to determine if the token is good or not (does not throw an error, and the change stream object appears to be the same regardless)
    // therefore, I'm using a timeout since theoretically the callback on the resuming change stream should be triggered well before x seconds
    // if not, we will at least have a backup change stream
  }
  // handle error events
  errListener(userNsp, fixerNsp, changeStream, resumeToken, err);
}

module.exports = watcher;