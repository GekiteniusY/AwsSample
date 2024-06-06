// 成功

const crypto = require("crypto");

// 使用例
const policyObject = {
  expiration: "2015-12-30T12:00:00.000Z",
  conditions: [
    { bucket: "sigv4examplebucket" },
    ["starts-with", "$key", "user/user1/"],
    { acl: "public-read" },
    {
      success_action_redirect:
        "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html",
    },
    ["starts-with", "$Content-Type", "image/"],
    { "x-amz-meta-uuid": "14365123651274" },
    { "x-amz-server-side-encryption": "AES256" },
    ["starts-with", "$x-amz-meta-tag", ""],
    {
      "x-amz-credential":
        "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request",
    },
    { "x-amz-algorithm": "AWS4-HMAC-SHA256" },
    { "x-amz-date": "20151229T000000Z" },
  ],
};

// CHECK: つまづきポイント
function createPolicyString(policyObject) {
  let policyString =
    '{ "expiration": "' +
    policyObject.expiration +
    '",\r\n  "conditions": [\r\n';

  policyObject.conditions.forEach((condition, index) => {
    if (Array.isArray(condition)) {
      policyString += '    ["' + condition.join('", "') + '"]';
    } else {
      const keys = Object.keys(condition);
      keys.forEach((key, keyIndex) => {
        if (key === "x-amz-date") {
          policyString += '    {"' + key + '": "' + condition[key] + '" }';
        } else if (key === "x-amz-credential") {
          policyString += "\r\n";
          policyString += '    {"' + key + '": "' + condition[key] + '"}';
        } else {
          policyString += '    {"' + key + '": "' + condition[key] + '"}';
        }
        if (keyIndex < keys.length - 1) {
          policyString += ", ";
        }
      });
    }
    if (index < policyObject.conditions.length - 1) {
      policyString += ",\r\n";
    }
  });

  policyString += "\r\n  ]\r\n}";

  return policyString;
}

function encodePolicyToBase64(policyObject) {
  const policyString = createPolicyString(policyObject);
  return Buffer.from(policyString).toString("base64");
}

const policyString = createPolicyString(policyObject);
console.log(policyString);
const base64EncodedPolicy = encodePolicyToBase64(policyObject);
console.log(base64EncodedPolicy);

// ========================================================================

// const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const SECRET_ACCESS_KEY = "XXXXXXXXXXXXXXXXXXX";
const DATE = new Date("2015-12-29T00:00:00.000Z");
// CHECK: つまづきポイント
const AMZ_DATE = DATE.toISOString().slice(0, 10).replace(/-/g, "");
console.log("AMZ_DATE: ", AMZ_DATE);
const REGION = "us-east-1";

// ========================================================================

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

async function createSigningKey(secretKey, date, region) {
  const kDate = hmacSha256("AWS4" + secretKey, date);
  console.log("kDate: ", kDate.toString("hex"));
  const kRegion = hmacSha256(kDate, region);
  console.log("kRegion: ", kRegion.toString("hex"));
  const kService = hmacSha256(kRegion, "s3");
  console.log("kService: ", kService.toString("hex"));
  const kSigning = hmacSha256(kService, "aws4_request");
  console.log("kSigning: ", kSigning.toString("hex"));
  return kSigning;
}

function arrayBufferToHex(buffer) {
  return buffer.toString("hex");
}

(async function () {
  const signingKey = await createSigningKey(
    SECRET_ACCESS_KEY,
    AMZ_DATE,
    REGION
  );
  const signature = hmacSha256(signingKey, base64EncodedPolicy);
  console.log("signature: ", signature);
  console.log("signatureHex: ", arrayBufferToHex(signature));
})();
