// Load environment variables
require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const querystring = require('querystring');
const passport = require('passport');
const session = require('express-session');
const FacebookStrategy = require('passport-facebook').Strategy;
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Supabase Client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Middleware for parsing JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set security headers
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'defaultsecret',
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// ✅ Facebook OAuth Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FB_APP_ID,
      clientSecret: process.env.FB_APP_SECRET,
      callbackURL: process.env.FB_CALLBACK_URL,
      profileFields: ['id', 'displayName', 'emails'],
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log('Facebook OAuth Profile:', profile);

      // Store user in Supabase
      const { data, error } = await supabase
        .from('profiles')
        .upsert([{ id: profile.id, full_name: profile.displayName, email: profile.emails[0].value }]);

      if (error) {
        console.error('Supabase error:', error);
        return done(error, null);
      }

      return done(null, { accessToken, profile });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// ✅ JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.userId = user.userId;
    next();
  });
};

// ✅ Basic Health Check Route
app.get('/', (req, res) => {
  res.send('App is running');
});

// ✅ User Registration (Email & Password)
app.post('/register', async (req, res) => {
  const { email, password, full_name } = req.body;

  const { user, error } = await supabase.auth.signUp({
    email,
    password,
    data: { full_name },
  });

  if (error) {
    return res.status(400).json({ msg: error.message });
  }

  res.json({ user });
});

// ✅ Facebook OAuth Routes
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email', 'pages_show_list', 'instagram_basic', 'instagram_content_publish'] }));

app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
  res.json({ user: req.user });
});

// ✅ Instagram OAuth Routes (via Facebook)
app.get('/auth/instagram', (req, res) => {
  const authUrl = `https://www.facebook.com/v17.0/dialog/oauth?${querystring.stringify({
    client_id: process.env.FB_APP_ID,
    redirect_uri: process.env.FB_REDIRECT_URI,
    scope: 'instagram_basic,instagram_content_publish,pages_show_list',
    response_type: 'code',
  })}`;
  res.redirect(authUrl);
});

app.get('/auth/instagram/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).json({ msg: 'Authorization code is missing' });

    const tokenResponse = await axios.get('https://graph.facebook.com/v17.0/oauth/access_token', {
      params: {
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        redirect_uri: process.env.FB_REDIRECT_URI,
        code,
      },
    });

    const userAccessToken = tokenResponse.data.access_token;
    res.json({ accessToken: userAccessToken });
  } catch (error) {
    console.error('Instagram OAuth error:', error.response?.data || error.message);
    res.status(500).json({ msg: 'An unexpected error occurred' });
  }
});

// ✅ Webhook Verification (Facebook & Instagram)
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token && mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('Webhook verified successfully.');
    res.status(200).send(challenge); // Required by Facebook
  } else {
    console.error('Webhook verification failed.');
    res.status(403).send('Forbidden');
  }
});

// ✅ Webhook Event Logging (POST /webhook)
app.post('/webhook', async (req, res) => {
  const event = req.body;
  console.log('Received Instagram Webhook Event:', JSON.stringify(event, null, 2));

  const { error } = await supabase
    .from('audit_logs')
    .insert([{ event_type: 'webhook_received', event_data: event }]);

  if (error) {
    console.error('Supabase Webhook Error:', error.message);
  }

  res.status(200).send('Event received');
});

// ✅ Global Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: 'An unexpected error occurred' });
});

// ✅ Start the Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
