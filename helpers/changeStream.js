export const closeChangeStream = (timeInMs = 60000, changeStream, responseSent, response) => {
  return new Promise((resolve) => {
      setTimeout(() => {
          console.log('Closing the change stream');
          if (!responseSent) response.sendStatus(408);
          changeStream.close();
          resolve();
      }, timeInMs)
  })
};