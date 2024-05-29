var crypto = require("crypto-browserify");

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest("hex");
}

// この関数を外部からアクセス可能にする
window.hmacSha256 = hmacSha256;
