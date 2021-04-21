const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
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

    //CODE FOR HASHING THE PASSWORD AT REGISTRATION SO ITS NOT STORED IN PLAIN TEXT
    let user = req.body;
    const rounds = process.env.BCRYPT_ROUNDS || 8;
    const hash = bcrypt.hashSync(user.password, rounds);

    user.password = hash;

    Users.add(user)
    .then((newUser)=>{
      res.status(200).json(newUser);
    })
    .catch((err)=>{
      res.status(500).json({message: err.message});
    })
});


router.post("/login", checkUsernameExists, (req, res, next) => {
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

    let { username, password } = req.body;

    Users.findBy(username)
    .then((foundUser)=>{
      if (foundUser && bcrypt.compareSync(foundUser.password, req.body.password)){
        const token = buildToken(foundUser);
        res.status(200).json({message: `Welcome ${username}`, token})
      } else {
        res.status(401).json({message: "Invalid Credentials"});
      }
    })
    .catch((err)=>{
      next(err);
    })


});

function buildToken(user){
  const payload = {
    subject: user.id,
    username: user.username,
    role_name: user.role_name
  }
  const config = {
    expiresIn: "1d"
  }
  return jwt.sign(payload, JWT_SECRET, config)
}


module.exports = router;
