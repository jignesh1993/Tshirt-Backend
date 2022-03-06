const User = require("../models/user");
const { validationResult } = require("express-validator");
var jwt = require("jsonwebtoken");
var expressJwt = require("express-jwt");
var { OAuth2Client } = require("google-auth-library");

const client = new OAuth2Client(
  "1072416019688-7pc4f0ml5lbq04dn8stagrv9tbto92en.apps.googleusercontent.com"
);

exports.signup = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: errors.array()[0].msg,
    });
  }

  const user = new User(req.body);
  user.save((err, user) => {
    if (err) {
      return res.status(400).json({
        err: "not able to save user in DB",
      });
    }
    res.json({
      name: user.name,
      email: user.email,
      id: user._id,
    });
  });
};

exports.signin = (req, res) => {
  const { email, password } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: errors.array()[0].msg,
    });
  }

  User.findOne({ email }, (err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "User email does not exists",
      });
    }

    if (!user.authenticate(password)) {
      return res.status(401).json({
        error: "email and password does not match",
      });
    }

    //create token
    const token = jwt.sign({ _id: user._id }, process.env.SECRET);

    //put token in cookie
    res.cookie("token", token, { expire: new Date() + 9999 });

    const { _id, name, email, role } = user;
    res.json({ token, user: { _id, name, email, role } });
  });
};

exports.loginWithGoogle = async (req, res) => {
  const { tokenId } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: errors.array()[0].msg,
    });
  }

  const result = await client.verifyIdToken({ idToken: tokenId });
  const loginEmail = result.payload.email;

  const user = await User.findOne({ email: loginEmail });
  if (user === null) {
    const newUser = {
      name: result.payload.name,
      email: result.payload.email,
      password: result.payload.sub,
    };
    const user = new User(newUser);
    const savedUser = await user.save(user);
    //create token
    const token = jwt.sign({ _id: savedUser._id }, process.env.SECRET);

    //put token in cookie
    res.cookie("token", token, { expire: new Date() + 9999 });

    const { _id, name, email, role } = savedUser;
    res.json({ token, user: { _id, name, email, role } });
  } else {
    //create token
    const token = jwt.sign({ _id: user._id }, process.env.SECRET);

    //put token in cookie
    res.cookie("token", token, { expire: new Date() + 9999 });

    const { _id, name, email, role } = user;
    res.json({ token, user: { _id, name, email, role } });
  }
};

exports.signout = (req, res) => {
  res.clearCookie("token");
  res.json({
    message: "User Signout successfully",
  });
};

//protected routes
exports.isSignedIn = expressJwt({
  secret: process.env.SECRET,
  userProperty: "auth",
});

//custome middlewares
exports.isAuthenticated = (req, res, next) => {
  let checker = req.profile && req.auth && req.profile._id == req.auth._id;
  if (!checker) {
    return res.status(403).json({
      error: "Access Denied",
    });
  }
  next();
};

exports.isAdmin = (req, res, next) => {
  if (req.profile.role === 0) {
    return res.status(403).json({
      error: "You are not an ADMIN, Aceess Denied",
    });
  }
  next();
};
