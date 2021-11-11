const router = require('express').Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require('../secrets'); // use this secret!
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const tokenBuilder = require('./token-builder');

router.post('/register', validateRoleName, async (req, res, next) => {
  try {
    const user = req.body;
    const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS);

    user.password = hash;
    const newUser = await Users.add(req.body);
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post('/login', checkUsernameExists, async (req, res, next) => {
 try{
   const  user = req.user
   if (bcrypt.compareSync(req.body.password, user.password)){
     const token = tokenBuilder(user)
     res.status(200).json({
       message: `${user.username} is back!`, token
     })
   } else{
     next({ status:401, message: 'invalid credentials'})
   }
 }catch(err){ 
   next(err)
 }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
