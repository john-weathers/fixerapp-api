const express = require('express');
const {
  currentWork, 
  findWork,
  cancelJob,
} = require('../../controllers/fixers.controller');
const router = express.Router();

router.get('/current', currentWork);
router.post('/find', findWork);
router.post('/cancel', cancelJob);

module.exports = router;