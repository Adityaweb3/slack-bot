const { WebClient } = require('@slack/web-api');
const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');

const slackClient = new WebClient(process.env.SLACK_BOT_TOKEN);
const app = express();

app.use(bodyParser.json());

const SHOP_ON_CALL_REGEX = /\bshop on[-\s]?call\b/i;

app.post('/api', async (req, res) => {
  const slackSignature = req.headers['x-slack-signature'];
  const requestBody = JSON.stringify(req.body);
  const timestamp = req.headers['x-slack-request-timestamp'];

  const hmac = crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET);
  const [version, hash] = slackSignature.split('=');
  hmac.update(`${version}:${timestamp}:${requestBody}`);
  const calculated = hmac.digest('hex');

  if (hash !== calculated) {
    return res.status(400).send('Verification failed');
  }

  if (req.body.type === 'url_verification') {
    return res.send({ challenge: req.body.challenge });
  }

  if (req.body.event && req.body.event.type === 'app_mention') {
    const text = req.body.event.text;

    if (SHOP_ON_CALL_REGEX.test(text)) {
      await slackClient.chat.postMessage({
        channel: process.env.SHOP_CHANNEL_ID,
        text: `🔔 Shop On-Call: "${text}"`,
      });
    }
  }

  res.status(200).send('ok');
});

module.exports = app;
