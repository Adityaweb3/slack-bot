const express = require('express');
const { WebClient } = require('@slack/web-api');
const crypto = require('crypto');

const app = express();
const slackClient = new WebClient(process.env.SLACK_BOT_TOKEN);

// 👇 Use raw body to verify Slack signature
app.use('/api', express.raw({ type: 'application/json' }));

// Regex to detect 'shop on call' variations in cleaned-up text
const SHOP_ON_CALL_REGEX = /shop[-\s]?on[-\s]?call/i;
// Your Slack user group ID for @shop-oncall
// const SHOP_ONCALL_SUBTEAM_ID = 'S08FE0Y4USK';
const SHOP_ONCALL_SUBTEAM_ID = process.env.SHOP_ONCALL_SUBTEAM_ID;

app.post('/api', async (req, res) => {
  try {
    const slackSignature = req.headers['x-slack-signature'];
    const timestamp = req.headers['x-slack-request-timestamp'];
    const rawBody = req.body.toString('utf8');

    // Validate Slack request signature
    const hmac = crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET);
    const [version, hash] = slackSignature.split('=');
    hmac.update(`${version}:${timestamp}:${rawBody}`);
    const calculated = hmac.digest('hex');

    if (calculated !== hash) {
      return res.status(400).send('Signature mismatch');
    }

    const body = JSON.parse(rawBody);
    const event = body.event;

    if (body.type === 'url_verification') {
      return res.status(200).send(body.challenge);
    }

    if (event && event.type === 'app_mention') {
      const rawText = event.text || '';
      console.log('Raw Slack text:', rawText);

      // Remove Slack mentions like <@USERID> or <!subteam^ID>
      const cleanedText = rawText.replace(/<[@!][^>]+>/g, '').trim();
      console.log('Cleaned text:', cleanedText);

      const containsSubteamMention = rawText.includes(`<!subteam^${SHOP_ONCALL_SUBTEAM_ID}>`);
      const matchesRegex = SHOP_ON_CALL_REGEX.test(cleanedText);
      console.log('Subteam ID match:', containsSubteamMention);
      console.log('Regex test result:', matchesRegex);

      if (containsSubteamMention || matchesRegex) {
        await slackClient.chat.postMessage({
          channel: process.env.SHOP_CHANNEL_ID,
          text: `🔔 Shop On-Call: "${rawText}"`,
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
