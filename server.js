const express = require("express");
const multer = require("multer");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const nedb = require("@seald-io/nedb");
const expressSession = require("express-session");
const nedbSessionStore = require("nedb-promises-session-store");
const bcrypt = require("bcrypt");
const cors = require('cors');

// configuration variables
let database = new nedb({
  filename: "database.txt",
  autoload: true,
});

let projectbase = new nedb({
  filename: "projectbase.txt",
  autoload: true,
});

const urlEncodedParser = bodyParser.urlencoded({
  extended: true,
});
const upload = multer({
  dest: "public/uploads",
});
const nedbSessionInit = nedbSessionStore({
  connect: expressSession,
  filename: "sessions.txt",
});
let userdatabase = new nedb({
  filename: "userdb.txt",
  autoload: true,
});

// initialize express library and settings
const app = express();
app.use(express.static("public"));
app.use(urlEncodedParser);
app.use(cookieParser());
app.use(cors());
app.use(
  expressSession({
    store: nedbSessionInit,
    cookie: {
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year for the session
    },
    secret: "supersecret123",
  })
);
app.set("view engine", "ejs");

function requiresAuthentication(req, res, next) {
  if (req.session.loggedInUser) {
    // go to the next thing
    // goes to the route that the middleware is blocking
    next();
  } else {
    res.redirect("/login?error=true");
  }
}

//Index Page
app.get("/", (request, response) => {
  /////////////////////////////////////
  // remove the if statement
  // if(request.session.loggedInUser){
  console.log(request.cookies.visits);

  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

  response.render("index.ejs", {
    visitsToSite: request.cookies.visits,
    user: request.session.loggedInUser,
  });
});

//Information Pages
app.get("/about", (request, response) => {
  console.log(request.cookies.visits);

  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

  response.render("information/about.ejs", {
    visitsToSite: request.cookies.visits,
    user: request.session.loggedInUser,
  });
});

app.get("/people", (request, response) => {
  console.log(request.cookies.visits);
  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

  response.render("information/people.ejs", {
    visitsToSite: request.cookies.visits,
    user: request.session.loggedInUser,
  });
});

app.get("/partnerships", (request, response) => {
  console.log(request.cookies.visits);
  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

  response.render("information/partnerships.ejs", {
    visitsToSite: request.cookies.visits,
    user: request.session.loggedInUser,
  });
});

app.get("/maker-in-residence", (request, response) => {
  console.log(request.cookies.visits);
  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

  response.render("information/maker.ejs", {
    visitsToSite: request.cookies.visits,
    user: request.session.loggedInUser,
  });
});

const fs = require('fs').promises;
const path = require('path');

app.get('/profile/:id', async (req, res, next) => {
  try {
    const raw = await fs.readFile(
      path.join(__dirname, 'views','information', 'profile.json'),
      'utf8'
    );
    const profile = JSON.parse(raw);

    if (profile.id !== req.params.id) return res.status(404).send('Not found');

    res.render('information/profile.ejs', {
      userName: req.session.loggedInUser,
      profile
    });
  } catch (err) {
    next(err);
  }
});


//Material Pages
app.get('/recipes', (req, res) => {
  let query = {};
  let sortQuery = { timestamp: -1 };

  projectbase.find(query).sort(sortQuery).exec((err, posts) => {
    if (err) {
      res.status(500).send(err);
      return;
    }

    res.render('materials/recipes.ejs', {
      posts: posts, // Pass the posts to the EJS template
      userName: req.session.loggedInUser,
    });
  });
});

//search, filter feature of recipe page
app.get('/recipes-data', (req, res) => {
  const { search = '', sort = 'year_desc', tag = '' } = req.query;  
  const sortMap = {
    year_desc: { timestamp: -1 },
    year_asc:  { timestamp:  1 },
    name_asc:  { title:      1 },
    name_desc: { title:     -1 },
  };

  // Escape any regex metacharacters so "c++" doesn't blow up
  const safe = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rx    = new RegExp(safe, 'i');          // case-insensitive

  const filter = {};
  if (search) filter.$or = [
    { title: rx }, { brief: rx }, { ingredients: rx }
  ];
  if (tag) filter.tag = tag;  

    projectbase
    .find(filter)
    .sort(sortMap[sort] || {})
    .exec((err, docs) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(docs);
    });
});

//Individual recipe page
app.get('/singleProject/:id', (request, response) => {
  const id = request.params.id;

  projectbase.findOne({ _id: id }, (err, doc) => {
    if (err || !doc) {
      return response.status(404).send('Project not found');
    }

    response.render('materials/singleProject.ejs', {
      post: doc,                           // **one** document
      visitsToSite: request.cookies.visits,
      userName: request.session.loggedInUser,
    });
  });
});

const uploadPictures = upload.fields([
  { name: "coverImage",    maxCount: 1  },
  { name: "galleryImages", maxCount: 10 }
]);

app.post(
  "/upload",
  requiresAuthentication,
  uploadPictures,
  (req, res) => {
    console.log(req.body);

    let currDate = new Date();

    let data = {
      text: req.body.text,
      date: currDate.toLocaleString(),
      timestamp: currDate.getTime(),
      likes: 0,
      comments: []
    };

    if (req.files?.coverImage?.[0]) {
      data.coverSrc = "/uploads/" + req.files.coverImage[0].filename;
    }

    if (req.files?.galleryImages?.length) {
      data.gallerySrc = req.files.galleryImages.map(f => "/uploads/" + f.filename);
    }

    database.insert(data, (err, newData) => {
      console.log(newData);
      res.redirect('back');
    });
  }
);

//Upload, update and delete projects feature
app.get("/form", (request, response) => {
  console.log(request.cookies.visits);
  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

  let query = {};

  let sortQuery = {
    timestamp: -1,
  };

  projectbase
    .find(query)
    .sort(sortQuery)
    .exec((err, data) => {
      response.render("uploadProjects/form.ejs", {
        posts: data,
        visitsToSite: request.cookies.visits,
        userName: request.session.loggedInUser,
      });
    });
});

app.post(
  "/uploadProject",
  requiresAuthentication,
  uploadPictures,                       // <-- replaces .single(...)
  (req, res) => {

    const now = new Date();

    // ---- core text fields ----
    const data = {
      title:        req.body.title,
      author:       req.body.author,
      email:        req.body.email,
      brief:        req.body.brief,
      ingredients:  req.body.ingredients,
      tag:          req.body.tag,
      tools:        req.body.tools,
      introduction: req.body.introduction,
      methods:      req.body.methods,
      curingT:      req.body.curingT,
      results:      req.body.results,
      physical:     req.body.physical,
      materialO:    req.body.materialO,
      otherO:       req.body.otherO,
      date:         now.toLocaleString(),
      timestamp:    now.getTime(),
    };

    // ---- picture paths ----
    if (req.files?.coverImage?.[0]) {
      data.coverSrc = "/uploads/" + req.files.coverImage[0].filename;
    }

    if (req.files?.galleryImages?.length) {
      data.gallerySrc = req.files.galleryImages.map(f => "/uploads/" + f.filename);
    }

    projectbase.insert(data, (err, newDoc) => {
      console.log("saved", newDoc);
      res.redirect("back");
    });
  }
);

app.post("/remove", requiresAuthentication, (req, res) => {
  let removedId = req.body.postId;
  // let referer = req.headers.referer;

  let query = {
    _id: removedId,
  };

  projectbase.remove(query, (err, numRemoved) => {
    console.log(`num removed elements ${numRemoved}`);
    res.redirect('back');
  });
});

// show the edit form
app.get("/edit/:id", requiresAuthentication, (req, res) => {
  projectbase.findOne({ _id: req.params.id }, (err, doc) => {
    if (err || !doc) return res.status(404).send("Project not found");
    res.render("uploadProjects/editProject.ejs", {
      post: doc,
      userName: req.session.loggedInUser,
    });
  });
});

// handle the update
app.post(
  "/updateProject",
  requiresAuthentication,
  uploadPictures,
  (req, res) => {
    const id = req.body.postId;

    // build the fields to update
    const updated = {
      title: req.body.title,
      author: req.body.author,
      email: req.body.email,
      brief: req.body.brief,
      ingredients: req.body.ingredients,
      tag: req.body.tag,
      tools: req.body.tools,
      introduction: req.body.introduction,
      methods: req.body.methods,
      curingT: req.body.curingT,
      results: req.body.results,
      physical: req.body.physical,
      materialO: req.body.materialO,
      otherO: req.body.otherO,
      // keep original date / timestamp unchanged
    };

    /* ─────────── COVER IMAGE ─────────── */
    // (a) user ticked "remove cover"
    if (req.body.removeCover)  updated.coverSrc = undefined;

    // (b) user uploaded a new cover
    if (req.files?.coverImage?.[0]) {
      updated.coverSrc = "/uploads/" + req.files.coverImage[0].filename;
    }


    /* ─────────── GALLERY ─────────── */
    // 1 ▸ keep whatever hidden inputs came back in *their new order*
    let gallery = [];
    if (req.body.existingGallery) {
      // existingGallery could be object or array depending on count
      const eg = req.body.existingGallery;
      gallery = Array.isArray(eg) ? eg : Object.values(eg);
    }

    // 2 ▸ drop anything the user ticked for deletion
    const toDelete = req.body.deleteGallery || [];
    gallery = gallery.filter(src => !toDelete.includes(src));

    // 3 ▸ append brand-new uploads at the end
    if (req.files?.galleryImages?.length) {
      gallery.push(
        ...req.files.galleryImages.map(f => "/uploads/" + f.filename)
      );
    }

    updated.gallerySrc = gallery.length ? gallery : undefined;

    projectbase.update(
      { _id: id },
      { $set: updated },
      {},
      (err, numReplaced) => {
        console.log(`updated ${numReplaced}`);
        res.redirect("back");      // or res.redirect('/') if you prefer
      }
    );
  }
);

//Login, register feature
app.get("/login", (req, res) => {
  // console.log(req.query.error)
  if (req.query.error) {
    res.render("utilities/login.ejs", { error: true });
  } else {
    res.render("utilities/login.ejs", {referer:req.headers.referer});
  }
});

app.get("/register", (req, res) => {
  res.render("utilities/register.ejs", {});
});

// code block for handling post requests from /auth and /signup
app.post("/signup", upload.single("profilePicture"), (req, res) => {
  // encrypting password so plain text is not store in db
  let hashedPassword = bcrypt.hashSync(req.body.password, 10);

  // local variable that holds my data obj to be inserted into userdb
  let data = {
    username: req.body.username,
    password: hashedPassword,
  };

  if (req.file) {
    data.filepath = "/uploads/" + req.file.filename;
  }

  userdatabase.insert(data, (err, dataInserted) => {
    console.log(dataInserted);
    res.redirect("/login");
  });
});

app.post("/authenticate", (req, res) => {
  let attemptLogin = {
    username: req.body.username,
    password: req.body.password,
  };

  let searchQuery = {
    username: attemptLogin.username,
  };

  userdatabase.findOne(searchQuery, (err, user) => {
    console.log("login attempted");
    if (err || user == null) {
      res.redirect("/login");
    } else {
      console.log("found user");

      // getting the stored password in the database
      let encPass = user.password;
      // using bcrypt to get the stored password, decrypt it and compare to attempted login password
      if (bcrypt.compareSync(attemptLogin.password, encPass)) {
        // storing login data to the session so the user does not have to login again
        let session = req.session;
        session.loggedInUser = attemptLogin.username;

        console.log("successful login");
        res.redirect(req.body.referer);
      } else {
        res.redirect("/login");
      }
    }
  });
});

app.get("/logout", (req, res) => {
  delete req.session.loggedInUser;
  res.redirect("/");
});

//Projects Pages
app.get("/projects", (request, response) => {
  console.log(request.cookies.visits);
  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

  response.render("projects/projects.ejs", {
    visitsToSite: request.cookies.visits,
    user: request.session.loggedInUser,
  });
});


//Inspiration Pages
app.get("/inspiration", (request, response) => {
  console.log(request.cookies.visits);
  if (request.cookies.visits) {
    let newVisit = parseInt(request.cookies.visits) + 1;
    response.cookie("visits", newVisit, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  } else {
    response.cookie("visits", 1, {
      expires: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
    });
  }

      response.render("inspirationAndGallery/inspiration.ejs", {
        visitsToSite: request.cookies.visits,
        user: request.session.loggedInUser,
      });
});

const port = 7626;
app.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
