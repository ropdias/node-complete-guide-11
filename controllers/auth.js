const bcrypt = require("bcryptjs");

const User = require("../models/user");

exports.getLogin = (req, res, next) => {
  // const isLoggedIn =
  //   req.get("Cookie").split(";")[0].trim().split("=")[1] === "true";
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    isAuthenticated: req.session.isLoggedIn,
  });
};

exports.getSignup = (req, res, next) => {
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    isAuthenticated: req.session.isLoggedIn,
  });
};

exports.postLogin = (req, res, next) => {
  // Cookies:
  // Max-Age=10 // to expire in 10 seconds
  // Domain=... // to set a domain
  // Secure  // to set that the cookie should only work if the page is served via https
  // HttpOnly // to set that we can't access the cookie value through client side javascript (scripts running in the browser)
  // The one above can be important security mechanism because it protects us against cross-site scripting attacks now
  // because now your client side javascript where someone could have injected malicious code can't read your cookies values and that
  // will be important later with authentication where a cookie will not store the sensitive information but and important part of
  // authenticating the user. This can be an extra security layer because now the cookie will still be attached to every request
  // that is sent to the server but you can't read the cookie value from inside the browser javascript code. (In the developer tool
  // you can still read it)
  // res.setHeader("Set-Cookie", "loggedIn=true; Max-Age=10");

  // The session object is added by the session middleware with app.use(session())
  // req.session.isLoggedIn = true;
  User.findById("630b9e957f011c15a62b4864")
    .then((user) => {
      if (user) {
        req.session.isLoggedIn = true;
        req.session.user = user; // This will remain a full mongoose model ONLY for this request
        req.session.save((err) => {
          if (err) console.log(err);
          res.redirect("/");
        });
      } else {
        console.log("User not found");
        req.session.isLoggedIn = false;
        req.session.save((err) => {
          if (err) console.log(err);
          res.redirect("/");
        });
      }
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
