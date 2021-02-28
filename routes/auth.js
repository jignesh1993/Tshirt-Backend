var express = require("express");
const { check } = require("express-validator");
var router = express.Router();
const { signout, signup, signin, isSignedIn } = require("../controllers/auth");

router.post(
  "/signup",
  [
    check("name", "Name should have 3 char").isLength({ min: 3 }),
    check("email", "enter valid email").isEmail(),
    check("password", "password should have 5 char").isLength({ min: 5 }),
  ],
  signup
);

router.post(
  "/signin",
  [
    check("email", "enter valid email").isEmail(),
    check("password", "password is required").isLength({ min: 1 }),
  ],
  signin
);

router.get("/signout", signout);

module.exports = router;
