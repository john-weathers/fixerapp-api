const express = require('express');
const { 
  fixRequest,
  searchRequest,
  cancelRequest,
} = require('../../controllers/users.controller');
const router = express.Router();

router.post('/new', fixRequest)
router.get('/search', searchRequest)
router.post('/cancel', cancelRequest) // add function

module.exports = router;