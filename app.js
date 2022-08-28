const path = require("path");

const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);

const errorControler = require("./controllers/error");
const User = require("./models/user");

const MONGODB_URI =
  "mongodb+srv://node-user:nodecomplete@cluster0.p1tfc.mongodb.net/shop-mongoose?retryWrites=true&w=majority";

const app = express();
const store = new MongoDBStore({
  uri: MONGODB_URI, // We could use a different database but for this example we are fine using the same one
  collection: "sessions", // You define here the collections you will use to store the sessions, we can use any name here
  // expires: ... // We could add a expires attribute to set when it should expire and mongodb will clean automatically
});

app.set("view engine", "ejs");
app.set("views", "views");

const adminRoutes = require("./routes/admin");
const shopRoutes = require("./routes/shop");
const authRoutes = require("./routes/auth");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

//'secret' is used for signing the hash which secretly stores our ID in the cookie. (In production this should be a long string value)
//'resave' means that the session will not be saved on every request that is done, but only if something changed in the session. (this improves performance)
//'saveUninitialized' this will ensure that no session gets saved for a request where it doesn't need to be saved because nothing was changed about it.
//'cookie' you can configure a cookie where you pass an object with properties like "maxAge" or "expires" or you can go with the default settings.
app.use(
  session({
    secret: "my secret",
    resave: false,
    saveUninitialized: false,
    store: store, // This attribute sets where we want to store the sessions
  })
);

// You need this middleware to get the full mongoose model so we can call all methods directly on that user for this request:
app.use((req, res, next) => {
  if (!req.session.user) {
    return next();
  }
  User.findById(req.session.user._id)
    .then((user) => {
      req.user = user;
      next();
    })
    .catch((err) => console.log(err));
})

app.use("/admin", adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.use(errorControler.get404);

mongoose
  .connect(MONGODB_URI)
  .then((result) => {
    User.findOne().then((user) => {
      if (!user) {
        const user = new User({
          name: "Rodrigo",
          email: "test@test.com",
          cart: { items: [] },
        });
        user.save();
      }
    });
    app.listen(3000);
  })
  .catch((err) => {
    console.log(err);
  });
