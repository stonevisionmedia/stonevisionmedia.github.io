/************************************************************
 * app.js — Consolidated Code w/ Cron for Instagram Refresh,
 *          Facebook, Instagram, Twitter & TikTok placeholders
 ************************************************************/

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
const { v4: uuidv4 } = require('uuid');

// Added node-cron
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;

// For rate limiting behind certain proxies (e.g., Render)
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

// Rate Limiter
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

/************************************************************
 * CRON JOB (using node-cron) — Refresh Instagram Tokens
 * Runs daily at midnight UTC
 ************************************************************/
cron.schedule('0 0 * * *', async () => {
  console.log('Running daily cron job to refresh Instagram tokens');

  try {
    // 1) Fetch all IG connections
    const { data: igConnections, error: igError } = await supabase
      .from('social_connections')
      .select('*')
      .eq('platform', 'instagram');

    if (igError) {
      console.error('Error fetching IG connections in cron:', igError);
      return;
    }

    // 2) For each IG connection, call the refresh endpoint
    for (const conn of igConnections) {
      const refreshUrl = 'https://graph.instagram.com/refresh_access_token';
      const params = {
        grant_type: 'ig_refresh_token',
        access_token: conn.page_access_token,
      };

      try {
        const resp = await axios.get(refreshUrl, { params });
        const newToken = resp.data.access_token;

        // 3) Update DB with the new token
        await supabase.from('social_connections').upsert({
          id: conn.id,
          user_id: conn.user_id,
          platform: 'instagram',
          page_id: conn.page_id,
          page_access_token: newToken,
        });

        console.log(`Refreshed IG token for user_id=${conn.user_id}`);
      } catch (e) {
        console.error(
          `Failed to refresh IG token for user_id=${conn.user_id}`,
          e.response?.data || e
        );
      }
    }

    console.log('Instagram token refresh cron job complete');
  } catch (error) {
    console.error('Cron job error:', error);
  }
});

/************************************************************
 * PASSPORT FACEBOOK STRATEGY
 ************************************************************/
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

        // 1) Upsert user into "profiles"
        const { data: upsertData, error: upsertError } = await supabase
          .from('profiles')
          .upsert({
            id: uuidv4(),
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

        // 2) Store the user-level Facebook token in "social_connections"
        //    We'll set page_id=null to indicate it's a user-level token
        const { data: connData, error: connError } = await supabase
          .from('social_connections')
          .upsert({
            id: uuidv4(),
            user_id: userId,
            platform: 'facebook',
            page_id: null,
            page_access_token: accessToken,
          })
          .select()
          .single();

        if (connError) {
          console.error(
            '❌ Upsert error in "social_connections" (FB user token):',
            connError
          );
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

/************************************************************
 * BASIC ROUTES
 ************************************************************/
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

/************************************************************
 * FACEBOOK OAUTH
 ************************************************************/
app.get(
  '/auth/facebook',
  passport.authenticate('facebook', {
    scope: [
      'email',
      'pages_show_list',
      'pages_manage_posts',
      // If also managing Instagram on the same FB app:
      'instagram_basic',
      'instagram_content_publish',
      'pages_read_user_content',
    ],
  })
);

app.get(
  '/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    return res.json({ msg: 'Facebook OAuth successful' });
  }
);

/************************************************************
 * FETCH & STORE PAGES (FACEBOOK)
 ************************************************************/
app.get('/facebook/pages', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;

    // 1) Find user-level FB token in social_connections (page_id=null)
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
        .json({ msg: 'No user-level FB token found for this user.' });
    }

    const userToken = connData.page_access_token;
    if (!userToken) {
      return res
        .status(400)
        .json({ msg: 'No valid Facebook user token found.' });
    }

    // 2) Fetch user’s pages from Facebook
    const pagesResponse = await axios.get(
      `https://graph.facebook.com/v17.0/me/accounts?access_token=${userToken}`
    );
    const pages = pagesResponse.data.data || [];

    // 3) Store each page's token
    for (const p of pages) {
      const { id: fbPageId, access_token: fbPageToken } = p;

      await supabase.from('social_connections').upsert({
        id: uuidv4(),
        user_id: userId,
        platform: 'facebook',
        page_id: fbPageId,
        page_access_token: fbPageToken,
      });
    }

    res.json({
      msg: 'Successfully stored Facebook page tokens',
      pageCount: pages.length,
    });
  } catch (error) {
    console.error('Error fetching/storing FB pages:', error.response?.data || error);
    res.status(500).json({ msg: 'Failed to fetch/store page tokens' });
  }
});

/************************************************************
 * POST TO FACEBOOK PAGES
 ************************************************************/
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
        .json({ msg: 'No matching FB page token found. Did you run /facebook/pages?' });
    }

    const fbPageId = connData.page_id;
    const fbPageToken = connData.page_access_token;

    // 2) Construct Graph API call
    let postUrl = `https://graph.facebook.com/v17.0/${fbPageId}/feed`;
    let postData = {
      message,
      access_token: fbPageToken,
    };

    if (media_url) {
      // If media_url is provided, post to /photos
      postUrl = `https://graph.facebook.com/v17.0/${fbPageId}/photos`;
      postData = {
        url: media_url,
        caption: message,
        access_token: fbPageToken,
      };
    }

    // 3) Make the post request
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

/************************************************************
 * INSTAGRAM OAUTH — SHORT-LIVED → LONG-LIVED
 ************************************************************/
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
    if (!code) {
      return res.status(400).json({ msg: 'Authorization code is missing' });
    }

    // 1) Get short-lived token
    const tokenResponse = await axios.get('https://graph.facebook.com/v17.0/oauth/access_token', {
      params: {
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        redirect_uri: process.env.FB_REDIRECT_URI,
        code,
      },
    });
    const shortLivedToken = tokenResponse.data.access_token;
    console.log('🔑 IG Short-Lived Token:', shortLivedToken);

    // 2) Exchange short-lived for long-lived token
    const exchangeResponse = await axios.get('https://graph.instagram.com/access_token', {
      params: {
        grant_type: 'ig_exchange_token',
        client_secret: process.env.FB_APP_SECRET,
        access_token: shortLivedToken,
      },
    });
    const longLivedToken = exchangeResponse.data.access_token;
    const expiresIn = exchangeResponse.data.expires_in; // ~60 days
    console.log('🔑 IG Long-Lived Token:', longLivedToken, 'Expires in:', expiresIn);

    // In a real flow, you'd have a known user ID from a JWT
    // For demonstration only:
    const tempUserId = uuidv4();

    // 3) Store the IG token in social_connections
    const { data: igConnData, error: igConnError } = await supabase
      .from('social_connections')
      .upsert({
        id: uuidv4(),
        user_id: tempUserId,
        platform: 'instagram',
        page_id: null,          // If you have an IG Business Account ID, store it here
        page_access_token: longLivedToken,
      })
      .select()
      .single();

    if (igConnError) {
      console.error('❌ Upsert error in "social_connections" (IG token):', igConnError);
      return res.status(500).json({ msg: 'Error storing IG token' });
    }

    res.json({
      msg: 'Instagram OAuth successful',
      user_id: tempUserId,
      instagram_token: longLivedToken,
      expires_in: expiresIn,
    });
  } catch (error) {
    console.error('Instagram OAuth error:', error.response?.data || error.message);
    res.status(500).json({ msg: 'Instagram OAuth flow failed' });
  }
});

/************************************************************
 * POST TO INSTAGRAM (Placeholder)
 ************************************************************/
app.post('/post/instagram', authenticateToken, async (req, res) => {
  try {
    const { message, media_url, ig_business_id } = req.body;
    const userId = req.userId.toString();

    // 1) Fetch the IG token from social_connections
    const { data: connData, error: connError } = await supabase
      .from('social_connections')
      .select('page_id, page_access_token')
      .eq('user_id', userId)
      .eq('platform', 'instagram')
      .eq('page_id', ig_business_id) // or the IG business ID
      .single();

    if (connError || !connData) {
      return res
        .status(400)
        .json({ msg: 'No matching IG token found. Did you link your IG Business account?' });
    }

    const igToken = connData.page_access_token;

    // 2) Create media object
    const creationResp = await axios.post(
      `https://graph.facebook.com/v17.0/${ig_business_id}/media`,
      {
        image_url: media_url,
        caption: message,
        access_token: igToken,
      }
    );
    const creationId = creationResp.data.id;
    console.log('🔧 IG creationId:', creationId);

    // 3) Publish media
    const publishResp = await axios.post(
      `https://graph.facebook.com/v17.0/${ig_business_id}/media_publish`,
      {
        creation_id: creationId,
        access_token: igToken,
      }
    );
    console.log('✅ IG publish response:', publishResp.data);

    // 4) Store the post in DB
    await supabase.from('posts').insert([
      {
        id: uuidv4(),
        platform: 'instagram',
        content: message,
        media_url: media_url || null,
        status: 'published',
        user_id: userId,
        scheduled_time: new Date(),
        published_at: new Date(),
      },
    ]);

    res.json({ msg: 'Instagram post successful', publishData: publishResp.data });
  } catch (error) {
    console.error('Instagram Post Error:', error.response?.data || error.message);
    res.status(500).json({ msg: 'Error posting to Instagram' });
  }
});

/************************************************************
 * TOKEN REFRESH DEMO ROUTES
 * (We replaced this with node-cron above, but you can keep 
 *  this route if you want a manual refresh endpoint.)
 ************************************************************/
app.get('/refresh/instagram', async (req, res) => {
  try {
    // 1) Find all IG connections
    const { data: igConnections } = await supabase
      .from('social_connections')
      .select('*')
      .eq('platform', 'instagram');

    for (const conn of igConnections) {
      const refreshUrl = 'https://graph.instagram.com/refresh_access_token';
      const params = {
        grant_type: 'ig_refresh_token',
        access_token: conn.page_access_token,
      };
      try {
        const resp = await axios.get(refreshUrl, { params });
        const newToken = resp.data.access_token;

        await supabase.from('social_connections').upsert({
          id: conn.id,
          user_id: conn.user_id,
          platform: 'instagram',
          page_id: conn.page_id,
          page_access_token: newToken,
        });
      } catch (e) {
        console.error(`Failed to refresh IG token for user ${conn.user_id}`, e);
      }
    }

    res.json({ msg: 'Refreshed all IG tokens' });
  } catch (error) {
    console.error('IG Refresh Error:', error.message);
    res.status(500).json({ msg: 'Error refreshing IG tokens' });
  }
});

/************************************************************
 * TIKTOK & TWITTER PLACEHOLDERS
 ************************************************************/
app.get('/auth/tiktok', (req, res) => {
  res.send('TikTok OAuth not implemented');
});

app.get('/auth/tiktok/callback', async (req, res) => {
  res.send('TikTok callback not implemented');
});

app.post('/post/tiktok', authenticateToken, async (req, res) => {
  res.json({ msg: 'Placeholder for TikTok posting' });
});

app.get('/auth/twitter', (req, res) => {
  res.send('Twitter OAuth not implemented');
});

app.get('/auth/twitter/callback', async (req, res) => {
  res.send('Twitter callback not implemented');
});

app.post('/post/twitter', authenticateToken, async (req, res) => {
  res.json({ msg: 'Placeholder for Twitter posting' });
});

/************************************************************
 * WEBHOOK VERIFICATION (GET)
 ************************************************************/
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token && mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ Webhook verified successfully.');
    return res.status(200).send(challenge);
  }
  return res.status(200).send('Webhook is active and listening.');
});

/************************************************************
 * WEBHOOK HANDLING (POST)
 ************************************************************/
app.post('/webhook', async (req, res) => {
  console.log(
    'Received Instagram/Facebook Webhook Event:',
    JSON.stringify(req.body, null, 2)
  );

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

/************************************************************
 * GLOBAL ERROR HANDLER
 ************************************************************/
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: 'An unexpected error occurred' });
});

/************************************************************
 * START SERVER
 ************************************************************/
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
