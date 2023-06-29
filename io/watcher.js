const Request = require('../models/Request');
const { errListener } = require('./watcherHelpers');

const timeout = (attemptNumber) => {
  return new Promise((res, rej) => {
    setTimeout(() => {
      res('timeout over');
    }, attemptNumber * 3000)
  })
}

const watcher = async (userNsp, fixerNsp, resumeToken, retryNumber) => {
  let changeStream;
  if (retryNumber) {
    await timeout(retryNumber);
    retryNumber += 1;
  } else {
    retryNumber = 1;
  }

  const pipeline = [
    {
      $match: {
        operationType: 'update',
      }
    }
  ]

  const err = {
    state: false,
  }

  // make sure a change stream is continuously open (but not more than one for any significant amount of time) and properly resumed if applicable
  if (!resumeToken) {
    changeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
      resumeToken = change._id;
      const fullDocument = change.fullDocument
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
      const fullDocument = change.fullDocument;
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
        changeStream.removeAllListeners('error');
        changeStream.close()
        const newChangeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
          resumeToken = change._id;
          const fullDocument = change.fullDocument;
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
            fixerNsp.to(String(fullDocument._id)).emit('job update', {
              currentStatus: fullDocument.currentStatus,
              trackerStage: fullDocument.trackerStage,
              quote: fullDocument?.quote,
              workStartedAt: fullDocument?.workStartedAt,
            });
          }
        })
        // handle error events
        errListener(userNsp, fixerNsp, newChangeStream, resumeToken, watcher, retryNumber);
      }
    }, 10000)
  }
  // handle error events
  errListener(userNsp, fixerNsp, changeStream, resumeToken, watcher, retryNumber, err);
}

module.exports = watcher;