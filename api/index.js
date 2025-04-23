const express = require('express');
const { WebClient } = require('@slack/web-api');
const crypto = require('crypto');

const app = express();
const slackClient = new WebClient(process.env.SLACK_BOT_TOKEN);

// 👇 Use raw body to verify Slack signature
app.use('/api', express.raw({ type: 'application/json' }));
const SHOP_ON_CALL_REGEX = /\bshop[-\s]?on(?:[-\s]?|)call\b/i;

app.post('/api', async (req, res) => {
  try {
    const slackSignature = req.headers['x-slack-signature'];
    const timestamp = req.headers['x-slack-request-timestamp'];
    const rawBody = req.body.toString('utf8');

    const hmac = crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET);
    const [version, hash] = slackSignature.split('=');
    hmac.update(`${version}:${timestamp}:${rawBody}`);
    const calculated = hmac.digest('hex');

    if (calculated !== hash) {
      return res.status(400).send('Signature mismatch');
    }

    const body = JSON.parse(rawBody);
    console.log('Event received:', JSON.stringify(body.event, null, 2));
    if (body.type === 'url_verification') {
      return res.status(200).send(body.challenge);
    }

    if (body.event && body.event.type === 'app_mention') {
      const text = body.event.text;
      console.log('Mention text:', text);
      console.log('Regex test result:', SHOP_ON_CALL_REGEX.test(text));

      if (SHOP_ON_CALL_REGEX.test(text)) {
        await slackClient.chat.postMessage({
          channel: process.env.SHOP_CHANNEL_ID,
          text: `🔔 Shop On-Call: "${text}"`,
        });
      }
    }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('Error handling Slack event:', err);
    return res.status(500).send('Internal Server Error');
  }
});

module.exports = app;
