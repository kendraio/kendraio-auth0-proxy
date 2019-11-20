require('dotenv').config();

const express = require('express');
const app = express();
const port = 3000;
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const cors = require('cors');
const axios = require('axios');

// Create middleware for checking the JWT
const checkJwt = jwt({
  // Dynamically provide a signing key based on the kid in the header and the singing keys provided by the JWKS endpoint.
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.DOMAIN}/.well-known/jwks.json`
  }),

  // Validate the audience and the issuer.
  audience: `https://${process.env.DOMAIN}/api/v2/`,
  issuer: `https://${process.env.DOMAIN}/`,
  algorithms: ['RS256']
});

app.use(cors());
app.use(require('body-parser').json());

app.post('/refresh', async (req, res) => {
  const {refreshToken} = req.body;
  if (!refreshToken) {
    return res.status(400).send();
  }
  try {
    const result = await getFromRefreshToken(refreshToken);
    return res.json(result);
  } catch (e) {
    return res.status(403).send({message: e.message});
  }
});

app.get('/', (req, res) => res.send('Hello'));

app.post('/', checkJwt, async (req, res) => {
  if (!req.user.sub) {
    return res.status(400).send();
  }
  try {
    const profile = await getProfile(req.user.sub);
    return res.json(profile);
  } catch (e) {
    console.log(e);
    return res.status(403).send({message: e.message});
  }
});
app.listen(port, () => console.log(`Listening on port ${port}!`));


async function getProfile(userId) {
  const {data} = await axios({
    method: 'post',
    url: `https://${process.env.DOMAIN}/oauth/token`,
    headers: {'content-type': 'application/json'},
    data: {
      "client_id": process.env.CLIENT_ID,
      "client_secret": process.env.CLIENT_SECRET,
      "audience": `https://${process.env.DOMAIN}/api/v2/`,
      "grant_type": "client_credentials"
    }
  });
  const {access_token} = data;

  const {data: profile} = await axios({
    method: 'get',
    url: `https://${process.env.DOMAIN}/api/v2/users/${userId}`,
    headers: {authorization: `Bearer ${access_token}`}
  });

  return profile;
}

async function getFromRefreshToken(refreshToken) {
  const {data} = await axios({
    method: 'post',
    url: `https://www.googleapis.com/oauth2/v4/token`,
    headers: {'content-type': 'application/json'},
    data: {
      "client_id": process.env.G_ID,
      "client_secret": process.env.G_SECRET,
      "refresh_token": `${refreshToken}`,
      "grant_type": "refresh_token"
    }
  });
  return data;
}
