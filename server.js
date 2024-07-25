const express = require("express");
const jwt = require("jsonwebtoken");
const session = require("express-session");

const app = express();
let users = [];
let peers = [];

const isValid = (username) => {
  let newarray = users.filter((item) => {
    return item.username === username;
  });
  return newarray.length === 0;
};

const verify = (username, password) => {
  let newarray = users.filter((item) => {
    return item.username === username && item.password === password;
  });
  return newarray.length !== 0;
};

app.use(express.json());

app.use(
  session({
    secret: "fingerprint_customer",
    resave: true,
    saveUninitialized: true,
  })
);

app.use("/peers", function auth(req, res, next) {
  if (req.session.authorization) {
    let token = req.session.authorization["accessToken"]; // Access Token

    jwt.verify(token, "access", (err, user) => {
      if (!err) {
        console.log(">>>>", user);
        req.user = user; // Set authenticated user data on the request object
        next(); // Proceed to the next middleware
      } else {
        return res.status(403).json({ message: "User not authenticated" }); // Return error if token verification fails
      }
    });
  } else {
    return res.status(403).json({ message: "User not logged in" });
  }
});

app.get("/peers", function (req, res) {
  return res.status(200).json({ peers: peers });
});

app.post("/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password) {
    return res.status(404).json({ message: "Error logging in" });
  }

  // Authenticate user
  if (verify(username, password)) {
    // Generate JWT access token
    let accessToken = jwt.sign(
      {
        data: password,
      },
      "access",
      { expiresIn: 60 * 60 }
    );
    // Store access token and username in session
    req.session.authorization = {
      accessToken,
      username,
    };
    return res.status(200).send("User successfully logged in");
  } else {
    return res
      .status(208)
      .json({ message: "Invalid Login. Check username and password" });
  }
});

app.post("/register", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  if (!username || !password) {
    return res.status(404).json({ message: "username or password missing" });
  }
  if (!isValid(username)) {
    return res.status(404).json({ message: users });
  }
  users.push({ username: username, password: password });

  return res.status(200).json({ message: "User added Successfully" });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Logout failed" });
    } else {
      return res.status(200).json({ message: "User logged out successfully" });
    }
  });
});

const PORT = 5000;
app.listen(PORT, () =>
  console.log(`Server is running on http://localhost:${PORT}`)
);
