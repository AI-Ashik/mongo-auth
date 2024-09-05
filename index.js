const cookieParser = require("cookie-parser");
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userModel = require("./models/user");

const PORT = 3000;
const app = express();

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.render("index");
});

app.post("/create", (req, res) => {
  const { username, email, age, password } = req.body;

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      const createdUser = await userModel.create({
        username,
        email,
        age,
        password: hash,
      });
      const token = jwt.sign({ email }, "secret");
      res.cookie("token", token);
      res.send(createdUser);
    });
  });
});

app.get("/logout", (req, res) => {
  res.cookie("token", "");
  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { password, email } = req.body;
  const user = await userModel.findOne({ email });
  if (!user) return res.send("something went wrong");
  bcrypt.compare(password, user.password, (err, result) => {
    if (result) {
      const token = jwt.sign({ email: user.email }, "secret");
      res.cookie("token", token);
      return res.send("you are loggedin");
    }
    return res.send("you are not loggedin");
  });
});

// server listen
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
