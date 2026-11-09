const crypto = require("crypto");

module.exports = (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  try {
    const secret = process.env.LINK_SECRET;
    const token = req.query.token;

    if (!secret || secret.length < 32) {
      return res.status(500).send("Server configuration error");
    }

    if (!token || typeof token !== "string") {
      return res.status(400).send("Missing token");
    }

    const parts = token.split(".");
    if (parts.length !== 2) {
      return res.status(403).send("Invalid token");
    }

    const [payload, signature] = parts;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length ||
        !crypto.timingSafeEqual(a, b)) {
      return res.status(403).send("Invalid signature");
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (!data.fileId ||
        !data.exp ||
        data.exp <= Math.floor(Date.now() / 1000)) {
      return res.status(403).send("Link expired");
    }

    const links = JSON.parse(
      process.env.FILE_LINKS_JSON || "{}"
    );

    const destination = links[data.fileId];

    if (!destination) {
      return res.status(404).send("File not found");
    }

    const url = new URL(destination);

    const allowed = (
      process.env.ALLOWED_HOSTS || ""
    ).split(",").map(x => x.trim()).filter(Boolean);

    if (
      url.protocol !== "https:" ||
      !allowed.includes(url.hostname)
    ) {
      return res.status(403).send("Destination not allowed");
    }

    return res.redirect(302, url.href);

  } catch (error) {
    return res.status(403).send("Invalid or expired link");
  }
};
