const express = require('express');
const {
  currentWork, 
  findWork,
  updateDirections,
  handleArrival,
} = require('../../controllers/fixers.controller');
const router = express.Router();

router.get('/current', currentWork);
router.post('/find', findWork);
router.patch('/directions', updateDirections);
router.patch('/arrival', handleArrival)

module.exports = router;