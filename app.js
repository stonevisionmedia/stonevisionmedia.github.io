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
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Supabase Client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Middleware for parsing JSON and form data
app.use(express.json());
app.use(bodyParser.json());
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

// Configure Passport for Facebook OAuth
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

      const { data, error } = await supabase
        .from('profiles')
        .upsert([{ id: profile.id, full_name: profile.displayName, email: profile.emails?.[0]?.value }]);

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

// JWT Authentication Middleware
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

// Basic route to check if the app is running
app.get('/', (req, res) => {
  res.send('App is running');
});

/**
 * User Registration & Login
 */
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

/**
 * Facebook OAuth Routes
 */
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email', 'pages_show_list', 'instagram_basic', 'instagram_content_publish'] }));

app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
  res.json({ user: req.user });
});

/**
 * Instagram OAuth Routes (via Facebook)
 */
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

/**
 * Webhook Verification (GET Request)
 */
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token && mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ Webhook verified successfully.');
    return res.status(200).send(challenge);
  }

  // ✅ Fix: Allow browser access to `/webhook`
  return res.status(200).send('Webhook is active and listening.');
});


/**
 * Webhook Handling (POST Request)
 */
app.post('/webhook', async (req, res) => {
  console.log('Received Instagram Webhook Event:', JSON.stringify(req.body, null, 2));

  if (!req.body || typeof req.body !== 'object') {
    console.error('❌ Invalid webhook payload');
    return res.status(400).json({ msg: 'Invalid payload' });
  }

  try {
    const { error } = await supabase
      .from('audit_logs')
      .insert([{ event_type: 'webhook_received', event_data: req.body }]);

    if (error) {
      console.error('❌ Supabase Webhook Error:', error.message);
      return res.status(500).json({ msg: 'Error storing event' });
    }

    console.log('✅ Webhook event logged successfully');
    res.status(200).send('Event received');
  } catch (error) {
    console.error('❌ Error in webhook handler:', error.message);
    res.status(500).json({ msg: 'Internal Server Error' });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: 'An unexpected error occurred' });
});

app.post('/post/facebook', authenticateToken, async (req, res) => {
  try {
      const { message, media_url } = req.body;
      const userId = req.userId; // Ensures the user is authenticated

      // Fetch user's stored Facebook Page ID & Access Token from Supabase
      const { data, error } = await supabase
          .from('social_connections')
          .select('account_id, access_token')
          .eq('user_id', userId)
          .eq('platform', 'facebook')
          .single();

      if (error || !data) {
          return res.status(400).json({ msg: "Facebook Page not connected" });
      }

      const { account_id: pageId, access_token: pageAccessToken } = data;

      let postUrl = `https://graph.facebook.com/v17.0/${pageId}/feed`;
      let postData = { message, access_token: pageAccessToken };

      if (media_url) {
          postUrl = `https://graph.facebook.com/v17.0/${pageId}/photos`;
          postData = { url: media_url, caption: message, access_token: pageAccessToken };
      }

      const response = await axios.post(postUrl, postData);

      // Store post in Supabase
      await supabase.from('posts').insert([
          {
              platform: 'facebook',
              content: message,
              media_url: media_url || null,
              status: 'published',
              user_id: userId,
              scheduled_time: new Date(),
              published_at: new Date(),
          }
      ]);

      res.json({ msg: "Post successfully created!", response: response.data });
  } catch (error) {
      console.error('Facebook Post Error:', error.response?.data || error.message);
      res.status(500).json({ msg: "Error posting to Facebook" });
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
