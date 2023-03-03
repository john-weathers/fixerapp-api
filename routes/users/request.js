const express = require('express');
const { 
  fixRequest,
  currentRequest,
  cancelRequest,
} = require('../../controllers/users.controller');
const router = express.Router();

router.post('/new', fixRequest);
router.get('/current', currentRequest);
router.delete('/cancel', cancelRequest);

module.exports = router;