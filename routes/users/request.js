const express = require('express');
const { 
  fixRequest,
  currentRequest,
  cancelRequest,
  handleQuoteDecision,
} = require('../../controllers/users.controller');
const router = express.Router();

router.post('/new', fixRequest);
router.get('/current', currentRequest);
router.delete('/cancel', cancelRequest);
router.patch('/quote', handleQuoteDecision)

module.exports = router;