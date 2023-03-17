const ResumeToken = require('../models/ResumeToken');

const errListener = async (stream, token) => {
  stream.on('error', async () => {
    try {
      // if there's an error with the change stream, and resume token available, call watcher with token
      if (token) {
        watcher(io, token);
        await ResumeToken.create({
          collectionName: 'requests',
          token,
        })
      } else {
        // no token cached, try to get backup token from database
        let backupToken;
        try {
          backupToken = await ResumeToken.find({ collectionName: 'requests' }).sort({ _id: -1 }).limit(1).exec(); // find most recent resume token
        } catch (err) {
          console.log(err.message);
        }
        watcher(io, backupToken); // works regardless of any outcome with find, whether that is finding a token, not finding a token, or encountering an error
      }
      stream.close() // not sure if this will work or if it's necessary, but including to be safe
    } catch (err) {
      console.log(err.message);
    }
  });
}

module.exports = {
  errListener,
}