// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require("express").Router();
const bcrypt = require("bcryptjs");
const User = require("../users/users-model");
const {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
} = require("./auth-middleware")
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post("/register", checkPasswordLength, checkUsernameFree, async (req, res, next) => {
  const { username, password } = req.body
  const hash = bcrypt.hashSync(password, 8) // 2 ^ 10

  User.add({ username, password: hash })
  .then(saved => {
    res.status(201).json({ user_id: saved.user_id, username: saved.username });
  })
  .catch(next)
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
  router.post("/login", checkUsernameExists, async (req, res, next) => {
    const { username, password } = req.body;
    User.findBy({ username }).first()  // Now, username is properly defined
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    })
    .catch(next);
  })  
//res.json("login")
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

  router.get("/logout", (req, res) => {
    if (req.session && req.session.user) {  
      req.session.destroy(err => {
        if (err) {
          res.status(500).json({ message: "failed to log out" });
        } else {
          res.clearCookie("chocolatechip");
          res.status(200).json({ message: "logged out" });
        }
      });
    } else {
      res.status(200).json({ message: "no session" });
    }
  })
  
 //res.json("logout")
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;