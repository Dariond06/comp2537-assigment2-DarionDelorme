const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { MongoClient, ObjectId } = require('mongodb');
const Joi = require('joi');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3333;

// Middleware
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

// MongoDB setup
const dbUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;
const client = new MongoClient(dbUri);

let db;
let usersCollection;

async function start() {
  await client.connect();
  db = client.db();
  usersCollection = db.collection('users');
  app.listen(port, () => console.log(`Listening on http://localhost:${port}`));
}
start();

// Middleware functions
function isAuthenticated(req, res, next) {
  if (req.session.authenticated) return next();
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.user_type === 'admin') {
    return next();
  }
  
  req.permissionDenied = true;  
  res.status(403);  
  return next();  
}



// Routes
app.get('/', (req, res) => {
  res.render('index', { session: req.session, title: 'Home' });
});

// GET /signup
app.get('/signup', (req, res) => {
  res.render('signup', { 
    title: 'Sign Up', 
    session: req.session, 
    error: null // Ensure error is defined for the EJS template
  });
});

// POST /signup
app.post('/signup', async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    // Render the form again with the validation error
    return res.render('signup', { 
      title: 'Sign Up', 
      session: req.session, 
      error: error.details[0].message 
    });
  }

  const { name, email, password } = req.body;

  // Check if the user already exists
  const existingUser = await usersCollection.findOne({ email });
  if (existingUser) {
    return res.render('signup', { 
      title: 'Sign Up', 
      session: req.session, 
      error: 'Email already in use' 
    });
  }

  const hashed = await bcrypt.hash(password, 12);

  await usersCollection.insertOne({ name, email, password: hashed, user_type: 'user' });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.user_type = 'user';

  res.redirect('/members');
});


app.get('/login', (req, res) => {
  res.render('login', {
    title: 'Login',
    session: req.session,
    email: '',      
    error: ''        
  });
});



app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.render('login', {
        title: 'Login',
        session: req.session,
        error: 'Email not found',
        email
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render('login', {
        title: 'Login',
        session: req.session,
        error: 'Incorrect password',
        email
      });
    }

    // Login successful
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.user_type = user.user_type;
    req.session.user_id = user._id;

    res.redirect('/members');
  } catch (err) {
    console.error(err);
    return res.render('login', {
      title: 'Login',
      session: req.session,
      error: 'Something went wrong. Try again.',
      email
    });
  }
});


app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/members', isAuthenticated, (req, res) => {
  res.render('members', { name: req.session.name, session: req.session, title: 'Members' });
});

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
  if (req.permissionDenied) {
    return res.render('admin', { 
      users: [], 
      session: req.session, 
      title: 'Admin', 
      error: '403: You do not have permission to view this page.' 
    });
  }

  const users = await usersCollection.find().toArray();
  res.render('admin', { users, session: req.session, title: 'Admin' });
});



app.get('/promote/:id', isAuthenticated, isAdmin, async (req, res) => {
  await usersCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
});

app.get('/demote/:id', isAuthenticated, isAdmin, async (req, res) => {
  await usersCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
});

// 404 Page
app.use((req, res) => {
  res.status(404).render('404', { title: 'Page Not Found', session: req.session });
});
