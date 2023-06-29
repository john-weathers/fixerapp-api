const ResumeToken = require('../models/ResumeToken');

const errListener = async (userNsp, fixerNsp, stream, token, watcher, retryNumber, err) => {
  stream.on('error', async () => {
    err.state = true;
    try {
      // if there's an error with the change stream, and resume token available, call watcher with token
      if (token) {
        watcher(userNsp, fixerNsp, token, retryNumber);
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
          // console.log(err.message);
        }
        watcher(userNsp, fixerNsp, backupToken, retryNumber);
      }
      stream.close()
    } catch (err) {
      console.error(err);
    }
  });
}

module.exports = {
  errListener,
}