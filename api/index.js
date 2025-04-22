const express = require('express');
const { WebClient } = require('@slack/web-api');
const crypto = require('crypto');

const slackClient = new WebClient(process.env.SLACK_BOT_TOKEN);
const app = express();


app.use('/api', express.raw({ type: 'application/json' }));

const SHOP_ON_CALL_REGEX = /\bshop on[-\s]?call\b/i;

app.post('/api', async (req, res) => {
  const slackSignature = req.headers['x-slack-signature'];
  const timestamp = req.headers['x-slack-request-timestamp'];
  const requestBody = req.body.toString('utf8');

  const hmac = crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET);
  const [version, hash] = slackSignature.split('=');
  hmac.update(`${version}:${timestamp}:${requestBody}`);
  const calculated = hmac.digest('hex');

  if (hash !== calculated) {
    return res.status(400).send('Verification failed');
  }

  const body = JSON.parse(requestBody);

  if (body.type === 'url_verification') {
    return res.status(200).send(body.challenge);
  }

  if (body.event && body.event.type === 'app_mention') {
    const text = body.event.text;

    if (SHOP_ON_CALL_REGEX.test(text)) {
      await slackClient.chat.postMessage({
        channel: process.env.SHOP_CHANNEL_ID,
        text: `🔔 Shop On-Call: "${text}"`,
      });
    }
  }

  return res.status(200).send('ok');
});

module.exports = app;
