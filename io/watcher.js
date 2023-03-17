const Request = require('../models/Request');
const { errListener } = require('./watcherHelpers');

const watcher = async (io, resumeToken) => {
  // I think best here will be operationType: update && (updated currentStatus || updated trackerStage || updated location)
  const pipeline = [
    {
      $match: {
        operationType: 'update',
        'updateDescription.updatedFields.currentStatus': { $exists: true }, 
      }
    }
  ];
  let changeStream;
  let errState = false;

  // make sure a change stream is continuously open (but not more than one for any significant amount of time) and properly resumed if applicable
  if (!resumeToken) {
    changeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
      resumeToken = change._id;
      console.log(change);
      const fullDocument = change.fullDocument;
      io.emit('stream change', fullDocument);
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
      io.emit('stream change', fullDocument);
    })

    setTimeout(() => {
      if (!streamResponse && !errState) {
        changeStream.off('error', () => console.log('error listener removed'));
        changeStream.close()
        const newChangeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
          resumeToken = change._id;
          console.log(change);
          const fullDocument = change.fullDocument;
          io.emit('stream change', fullDocument);
        })
        // handle error events
        errListener(newChangeStream, resumeToken);
      }
    }, 10000) // NOTE: be aware that time may need to change or coming up with another way of validating the resume token may be needed
    // there are no ways that I have found to determine if the token is good or not (does not throw an error, and the change stream object appears to be the same regardless)
    // therefore, I'm using a timeout since theoretically the callback on the resuming change stream should be triggered well before x seconds
    // if not, we will at least have a backup change stream
  }
  // handle error events
  errListener(changeStream, resumeToken);
}

module.exports = watcher;