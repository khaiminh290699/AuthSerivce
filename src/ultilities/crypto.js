const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = {
  hash: async (str) => {
    return await bcryptjs.hash(str, 10);
  },

  compare: async (str, hash) => {
    return await bcryptjs.compare(str, hash)
  },

  sign: (payload) => {
    return jwt.sign(payload, process.env.PRIVATE_KEY, { algorithm: "HS256" });
  },

  verify: (token) => {
    return jwt.verify(token, process.env.PRIVATE_KEY);
  }
}