const express = require('express');
const { 
  fixRequest,
  currentRequest,
  cancelRequest,
  handleQuoteDecision,
  handleRating,
} = require('../../controllers/users.controller');
const router = express.Router();

router.post('/new', fixRequest);
router.get('/current', currentRequest);
router.delete('/cancel', cancelRequest);
router.patch('/quote', handleQuoteDecision)
router.patch('/rate-fixer', handleRating)

module.exports = router;