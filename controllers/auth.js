const bcrypt = require("bcryptjs");

const User = require("../models/user");

exports.getLogin = (req, res, next) => {
  // const isLoggedIn =
  //   req.get("Cookie").split(";")[0].trim().split("=")[1] === "true";
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: req.flash('error'), // What I stored in 'error' will be retrivied here, and after we get it, it will be removed from the session
  });
};

exports.getSignup = (req, res, next) => {
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  // The session object is added by the session middleware with app.use(session())
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        req.flash('error', 'Invalid email or password.'); // We use both (email and password) here so people don't know which part was wrong
        return res.redirect("/login");
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          // We enter here independent if the password match or not (doMatch is true if it's equal, otherwise its false)
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user; // This will remain a full mongoose model ONLY for this request
            req.session.save((err) => {
              if (err) console.log(err);
              res.redirect("/");
            });
          } else {
            console.log("Password is wrong !");
            req.session.isLoggedIn = false;
            req.session.user = null;
            req.session.save((err) => {
              if (err) console.log(err);
              res.redirect("/login");
            });
          }
        })
        .catch((err) => {
          // We enter here if something goes wrong with the compare function (not regarding if the password match or not)
          console.log(err);
          res.redirect("/login");
        });
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  // We will validate user input (like checking if it's the same password) in a later section
  // So will just ignore validation for now

  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        // We will just redirect for now and not inform the user
        return res.redirect("/signup");
      }
      return bcrypt
        .hash(password, 12)
        .then((hashedPassword) => {
          const user = new User({
            email: email,
            password: hashedPassword,
            cart: { items: [] },
          });
          return user.save();
        })
        .then((result) => {
          res.redirect("/login");
        })
        .catch((err) => {
          console.log(err);
        });
    })
    .catch((err) => {
      console.log(err);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
};
