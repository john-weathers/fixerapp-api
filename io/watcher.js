const Request = require('../models/Request');
const { errListener } = require('./watcherHelpers');

// don't think this needs to be async
const watcher = async (userNsp, fixerNsp, resumeToken) => {
  let changeStream;

  const pipeline = [
    {
      $match: {
        operationType: 'update',
      }
    }
  ]

  /*const pipeline = [
    {
      $match: {
        $and: [
          { operationType: 'update' },
          { $or: [
            { 'updateDescription.updatedFields.currentStatus': { $exists: true } }, // think about simplifying and sending on all updates
            { 'updateDescription.updatedFields.trackerStage': { $exists: true } }, // becuase it might not make a difference
            { 'updateDescription.updatedFields.fixerLocation': { $exists: true } },
            { 'updateDescription.updatedFields.eta': { $exists: true } },
          ] }
        ]
      }
    }
  ];*/
  const err = {
    state: false,
  }

  // make sure a change stream is continuously open (but not more than one for any significant amount of time) and properly resumed if applicable
  if (!resumeToken) {
    changeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
      resumeToken = change._id;
      console.log(change);
      const fullDocument = change.fullDocument
      console.log(fullDocument?.quote);
      userNsp.to(String(fullDocument._id)).emit('job update', {
        currentStatus: fullDocument.currentStatus,
        fixerLocation: fullDocument.fixerLocation.coordinates,
        trackerStage: fullDocument.trackerStage,
        eta: fullDocument.eta,
        quote: fullDocument?.quote,
      });
      const updatedFields = change.updateDescription.updatedFields;
      if (updatedFields?.fixerLocation) {
        delete updatedFields.fixerLocation;
      }
      if (Object.keys(updatedFields).length) {
        console.log('fixer update firing');
        fixerNsp.to(String(fullDocument._id)).emit('job update', {
          currentStatus: fullDocument.currentStatus,
          trackerStage: fullDocument.trackerStage,
          quote: fullDocument?.quote,
          workStartedAt: fullDocument?.workStartedAt,
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
      console.log(fullDocument?.quote);
      userNsp.to(String(fullDocument._id)).emit('job update', {
        currentStatus: fullDocument.currentStatus,
        fixerLocation: fullDocument.fixerLocation.coordinates,
        trackerStage: fullDocument.trackerStage,
        eta: fullDocument.eta,
        quote: fullDocument?.quote,
      });
      const updatedFields = change.updateDescription.updatedFields;
      if (updatedFields?.fixerLocation) {
        delete updatedFields.fixerLocation;
      }
      if (Object.keys(updatedFields).length) {
        console.log('fixer update firing');
        fixerNsp.to(String(fullDocument._id)).emit('job update', {
          currentStatus: fullDocument.currentStatus,
          trackerStage: fullDocument.trackerStage,
          quote: fullDocument?.quote,
          workStartedAt: fullDocument?.workStartedAt,
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
          console.log(fullDocument?.quote);
          userNsp.to(String(fullDocument._id)).emit('job update', {
            currentStatus: fullDocument.currentStatus,
            fixerLocation: fullDocument.fixerLocation.coordinates,
            trackerStage: fullDocument.trackerStage,
            eta: fullDocument.eta,
            quote: fullDocument?.quote,
          });
          const updatedFields = change.updateDescription.updatedFields;
          if (updatedFields?.fixerLocation) {
            delete updatedFields.fixerLocation;
          }
          if (Object.keys(updatedFields).length) {
            console.log('fixer update firing');
            fixerNsp.to(String(fullDocument._id)).emit('job update', {
              currentStatus: fullDocument.currentStatus,
              trackerStage: fullDocument.trackerStage,
              quote: fullDocument?.quote,
              workStartedAt: fullDocument?.workStartedAt,
            });
          }
        })
        // handle error events
        errListener(userNsp, fixerNsp, newChangeStream, resumeToken, watcher);
      }
    }, 10000) // NOTE: be aware that time may need to change or coming up with another way of validating the resume token may be needed
    // there are no ways that I have found to determine if the token is good or not (does not throw an error, and the change stream object appears to be the same regardless)
    // therefore, I'm using a timeout since theoretically the callback on the resuming change stream should be triggered well before x seconds
    // if not, we will at least have a backup change stream
  }
  // handle error events
  errListener(userNsp, fixerNsp, changeStream, resumeToken, watcher, err);
}

module.exports = watcher;