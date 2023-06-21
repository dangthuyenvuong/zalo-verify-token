const Crypto = require("crypto");
const { config } = require("dotenv");
const express = require("express");
config();

const app = express();

app.use(express.json());

const SECRET_KEY = process.env.ZALO_SECRET_KEY;
const APP_ID = process.env.ZALO_APP_ID;

function createHash(data) {
  let content = JSON.stringify(data);
  const stringEncode = `${APP_ID}${content}${data.timestamp}${SECRET_KEY}`;

  const hash = Crypto.createHmac("sha256", SECRET_KEY)
    .update(stringEncode)
    .digest("hex");

  return hash;
}

const middlewareValidateXToken = (req, res, next) => {
  let xZeventSignature = req.headers["x-zevent-signature"];
  const hash = `mac=${createHash(req.body)}`;
  console.log(`hash: ${hash}, x-token: ${xZeventSignature}`);
  if (hash === xZeventSignature) {
    next();
  } else {
    res.status(400).json({ error: "X-ZEvent-Signature header Invalid" });
  }
};

app.post("/zalo-webhook", middlewareValidateXToken, (req, res) => {
  res.json({ success: true });
});

app.listen(3010, () => {
  console.log("Server listen on port 3000");
});
