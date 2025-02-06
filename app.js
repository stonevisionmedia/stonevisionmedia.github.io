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

// Trust Render proxies to fix rate limit issues
app.set('trust proxy', 1);

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
      console.log('🔄 Received Facebook OAuth callback.');
      console.log('✅ Facebook OAuth Success:', profile);

      const userId = profile.id.toString();
      const email = profile.emails?.[0]?.value || null;
      const fullName = profile.displayName || 'Unknown User';

      try {
        // 1️⃣ Check if the user exists by email
        const { data: existingUser, error: fetchError } = await supabase
          .from('profiles')
          .select('id')
          .eq('email', email)
          .single();

        if (fetchError && fetchError.code !== 'PGRST116') {
          console.error('❌ Supabase Fetch Error:', fetchError.message);
          return done(fetchError, null);
        }

        let finalUserId = userId; // Default to Facebook ID

        if (existingUser) {
          console.log('🔹 User already exists. Updating profile...');

          // Use existing UUID if it's already stored
          finalUserId = existingUser.id;

          // Update user record
          const { error: updateError } = await supabase
            .from('profiles')
            .update({ full_name: fullName, email })
            .eq('id', finalUserId);

          if (updateError) {
            console.error('❌ Supabase Update Error:', updateError.message);
            return done(updateError, null);
          }
        } else {
          console.log('🆕 Creating new user record...');

          // 2️⃣ Ensure a **UUID** is used for the new user
          const newUserId = crypto.randomUUID();

          const { error: insertError } = await supabase
            .from('profiles')
            .insert([{ id: newUserId, full_name: fullName, email }]);

          if (insertError) {
            console.error('❌ Supabase Insert Error:', insertError.message);
            return done(insertError, null);
          }

          finalUserId = newUserId; // Assign the new UUID
        }

        console.log('✅ User successfully stored in Supabase:', finalUserId);
        return done(null, { accessToken, profile });

      } catch (err) {
        console.error('❌ Unexpected Error:', err.message);
        return done(err, null);
      }
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

const { v4: uuidv4 } = require('uuid'); // Ensure this is at the top

app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), async (req, res) => {
    console.log('🔄 Received Facebook OAuth callback.');

    if (!req.user || !req.user.accessToken) {
        console.error('❌ No access token received');
        return res.status(400).json({ msg: 'Facebook OAuth failed' });
    }

    console.log('✅ Facebook OAuth Success:', req.user.profile);

    try {
        // Generate a valid UUID for Supabase
        const generatedUUID = uuidv4();

        // Ensure user profile details are extracted
        const fullName = req.user.profile.displayName || 'Unknown Name';
        const email = req.user.profile.emails?.[0]?.value || 'no-email@provided.com';
        const facebookId = req.user.profile.id; // Store Facebook ID separately

        console.log(`Generated UUID: ${generatedUUID}`);
        console.log(`Full Name: ${fullName}`);
        console.log(`Email: ${email}`);
        console.log(`Facebook ID: ${facebookId}`);

        // Insert user into Supabase with generated UUID
        const { data, error: insertError } = await supabase
            .from('profiles')
            .insert([
                {
                    id: generatedUUID, // Use the generated UUID
                    full_name: fullName,
                    email: email,
                    facebook_id: facebookId // Store Facebook ID in a separate column
                }
            ]);

        if (insertError) {
            console.error('❌ Supabase Insert Error:', insertError.message);
            return res.status(500).json({ msg: 'Database insert error' });
        }

        console.log('✅ User stored in Supabase:', generatedUUID);
        res.json({ msg: 'Facebook connected successfully!', user_id: generatedUUID });

    } catch (error) {
        console.error('❌ Unexpected Error:', error.message);
        res.status(500).json({ msg: 'An unexpected error occurred' });
    }
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
    const userId = req.userId.toString(); // Ensure ID is handled as TEXT

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
        user_id: userId, // Ensure correct format
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
