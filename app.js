/***********************************************
 * Final app.js — Uses "page_id" & "page_access_token" 
 * for Facebook Pages
 ***********************************************/

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
const { v4: uuidv4 } = require('uuid'); // For generating UUIDs if needed

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxies (Render, etc.)
app.set('trust proxy', 1);

// Initialize Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100,
  message: 'Too many requests, please try again later.',
});
app.use(limiter);

// Session + Passport
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'defaultsecret',
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

/*******************************************************
 * FACEBOOK OAUTH - PASSPORT STRATEGY
 ******************************************************/
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FB_APP_ID,
      clientSecret: process.env.FB_APP_SECRET,
      callbackURL: process.env.FB_CALLBACK_URL,
      profileFields: ['id', 'displayName', 'emails'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('🔄 FB OAuth callback. Profile:', profile);
        console.log('🔑 User Access Token:', accessToken);

        // Extract basic user info
        const fullName = profile.displayName || 'Unknown';
        const email =
          (profile.emails && profile.emails[0]?.value) ||
          'no-email@provided.com';

        // Upsert user into "profiles"
        const { data: upsertData, error: upsertError } = await supabase
          .from('profiles')
          .upsert({
            // Use email as a unique field if that's how you handle identity
            email,
            full_name: fullName,
          })
          .select()
          .single();

        if (upsertError) {
          console.error('❌ Upsert error in "profiles":', upsertError);
          return done(upsertError, null);
        }

        const userId = upsertData.id;
        console.log('✅ Upserted/Found user in "profiles". ID:', userId);

        // Store the user-level Facebook token in "social_connections"
        // We'll set page_id=null to indicate it's a user token
        const { data: connData, error: connError } = await supabase
          .from('social_connections')
          .upsert({
            id: uuidv4(), // Or let Supabase generate it if you prefer
            user_id: userId,
            platform: 'facebook',
            page_id: null,
            page_access_token: accessToken,
          })
          .select()
          .single();

        if (connError) {
          console.error('❌ Upsert error in "social_connections":', connError);
          return done(connError, null);
        }

        console.log(
          '✅ Stored user-level token in "social_connections". ID:',
          connData.id
        );

        // Done with Passport
        return done(null, { userId, accessToken, profile });
      } catch (err) {
        console.error('❌ Unexpected error in FB strategy:', err);
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// JWT Auth Middleware
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

/*******************************************************
 * BASIC ENDPOINTS
 ******************************************************/
app.get('/', (req, res) => {
  res.send('App is running');
});

// Registration
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

/*******************************************************
 * FACEBOOK OAUTH ROUTES
 ******************************************************/
app.get(
  '/auth/facebook',
  passport.authenticate('facebook', {
    scope: [
      'email',
      'pages_show_list',
      'pages_manage_posts',
      // If also managing Instagram:
      'instagram_basic',
      'instagram_content_publish',
      'pages_read_user_content',
    ],
  })
);

// Callback
app.get(
  '/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful login => the user-level token is stored.
    return res.json({ msg: 'Facebook OAuth successful' });
  }
);

/*******************************************************
 * FETCH & STORE PAGES
 ******************************************************/
/**
 * GET /facebook/pages
 * 1) Looks up the user-level FB token (page_id=null).
 * 2) Fetches all pages the user manages.
 * 3) Stores each page's page_id + page_access_token in social_connections.
 */
app.get('/facebook/pages', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;

    // 1) Fetch the user-level token
    const { data: connData, error: connError } = await supabase
      .from('social_connections')
      .select('*')
      .eq('user_id', userId)
      .eq('platform', 'facebook')
      .eq('page_id', null)
      .single();

    if (connError || !connData) {
      return res
        .status(400)
        .json({ msg: 'No user-level Facebook token found for this user.' });
    }

    const userToken = connData.page_access_token;
    if (!userToken) {
      return res
        .status(400)
        .json({ msg: 'No valid Facebook user token found.' });
    }

    // 2) Fetch pages from Facebook
    const pagesResponse = await axios.get(
      `https://graph.facebook.com/v17.0/me/accounts?access_token=${userToken}`
    );

    const pages = pagesResponse.data.data || [];
    console.log('🔎 FB /me/accounts =>', pages);

    // 3) Store each page with its token
    for (const p of pages) {
      const { id: fbPageId, access_token: fbPageToken } = p;

      // Upsert => if a record with the same user_id + platform + page_id 
      // exists, it updates. Otherwise, it creates new.
      await supabase.from('social_connections').upsert({
        id: uuidv4(), // If your table PK is "id" (text), we can generate a new one
        user_id: userId,
        platform: 'facebook',
        page_id: fbPageId,
        page_access_token: fbPageToken,
      });
    }

    res.json({
      msg: 'Successfully stored page tokens',
      pageCount: pages.length,
    });
  } catch (error) {
    console.error('Error fetching/storing FB pages:', error.response?.data || error);
    res.status(500).json({ msg: 'Failed to fetch/store page tokens' });
  }
});

/*******************************************************
 * FACEBOOK POST ENDPOINT
 ******************************************************/
// POST /post/facebook
// Requires: JWT, plus { page_id, message, media_url } in req.body
app.post('/post/facebook', authenticateToken, async (req, res) => {
  try {
    const { page_id, message, media_url } = req.body;
    const userId = req.userId.toString();

    if (!page_id) {
      return res.status(400).json({ msg: 'Missing "page_id" in request body.' });
    }

    // 1) Fetch the page-level token from social_connections
    const { data: connData, error: connError } = await supabase
      .from('social_connections')
      .select('page_id, page_access_token')
      .eq('user_id', userId)
      .eq('platform', 'facebook')
      .eq('page_id', page_id)
      .single();

    if (connError || !connData) {
      return res
        .status(400)
        .json({ msg: 'No matching page token found. Did you run /facebook/pages?' });
    }

    const fbPageId = connData.page_id;
    const fbPageToken = connData.page_access_token;

    // 2) Build the Graph API URL & data
    let postUrl = `https://graph.facebook.com/v17.0/${fbPageId}/feed`;
    let postData = { message, access_token: fbPageToken };

    if (media_url) {
      // If media_url is provided, post to /photos
      postUrl = `https://graph.facebook.com/v17.0/${fbPageId}/photos`;
      postData = { url: media_url, caption: message, access_token: fbPageToken };
    }

    // 3) Send the request
    const response = await axios.post(postUrl, postData);

    // 4) Store the post in "posts"
    await supabase.from('posts').insert([
      {
        id: uuidv4(),
        platform: 'facebook',
        content: message,
        media_url: media_url || null,
        status: 'published',
        user_id: userId,
        scheduled_time: new Date(),
        published_at: new Date(),
      },
    ]);

    res.json({ msg: 'Post successful!', response: response.data });
  } catch (error) {
    console.error('Facebook Post Error:', error.response?.data || error.message);
    res.status(500).json({ msg: 'Error posting to Facebook' });
  }
});

/*******************************************************
 * INSTAGRAM OAUTH
 ******************************************************/
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
    // If you want to store this in social_connections for "instagram", you can do so similarly:
    // await supabase.from('social_connections').insert({ ... });
    res.json({ accessToken: userAccessToken });
  } catch (error) {
    console.error('Instagram OAuth error:', error.response?.data || error.message);
    res.status(500).json({ msg: 'An unexpected error occurred' });
  }
});

/*******************************************************
 * WEBHOOK VERIFICATION (GET)
 ******************************************************/
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token && mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ Webhook verified successfully.');
    return res.status(200).send(challenge);
  }
  // Just respond with 200 for other GETs
  return res.status(200).send('Webhook is active and listening.');
});

/*******************************************************
 * WEBHOOK HANDLING (POST)
 ******************************************************/
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

/*******************************************************
 * GLOBAL ERROR HANDLER
 ******************************************************/
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: 'An unexpected error occurred' });
});

/*******************************************************
 * START SERVER
 ******************************************************/
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
