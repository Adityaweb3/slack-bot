const express = require('express');
const { WebClient } = require('@slack/web-api');
const crypto = require('crypto');

const app = express();
const slackClient = new WebClient(process.env.SLACK_BOT_TOKEN);

app.use('/api', express.raw({ type: 'application/json' }));

const SHOP_ONCALL_SUBTEAM_ID = process.env.SHOP_ONCALL_SUBTEAM_ID;

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
    const event = body.event;

    if (body.type === 'url_verification') {
      return res.status(200).send(body.challenge);
    }

    if (event && event.type === 'message' && event.subtype !== 'bot_message') {
      const text = event.text || '';
      const channelId = event.channel;
      const messageTs = event.ts;

      const containsSubteamMention = text.includes(`<!subteam^${SHOP_ONCALL_SUBTEAM_ID}>`);
      if (!containsSubteamMention) return res.status(200).send('No shop-oncall mention');

      const messagePermalink = await slackClient.chat.getPermalink({
        channel: channelId,
        message_ts: messageTs
      });

      // Post alert to designated channel
      await slackClient.chat.postMessage({
        channel: process.env.SHOP_CHANNEL_ID,
        blocks: [
          {
            type: "section",
            text: {
              type: "mrkdwn",
             text: `🚨 *Heads up!*\n🔔 @shop-oncall is mentioned in <#${channelId}>`
            }
          },
          {
            type: "actions",
            elements: [
              {
                type: "button",
                text: {
                  type: "plain_text",
                  text: "View Message"
                },
                url: messagePermalink.permalink
              }
            ]
          }
        ]
      });
    }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('Error handling Slack event:', err);
    return res.status(500).send('Internal Server Error');
  }
});

module.exports = app;
