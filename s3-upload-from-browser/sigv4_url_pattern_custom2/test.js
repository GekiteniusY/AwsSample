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
  return btoa(policyString);
}

const policyString = createPolicyString(policyObject);
console.log(policyString);
const base64EncodedPolicy = encodePolicyToBase64(policyObject);
console.log(base64EncodedPolicy);

// ========================================================================
// ========================================================================
// ========================================================================
// ========================================================================
// ========================================================================

const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const DATE = new Date("2015-12-29T00:00:00.000Z");
const AMZ_DATE = DATE.toISOString()
  .replace(/[:-]\.\d{3}/g, "")
  .split(".")[0];
const REGION = "us-east-1";

// ========================================================================
// ========================================================================

async function hmacSha256(key, msg) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(msg);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageData);
  return new Uint8Array(signature);
}

async function createSigningKey(secretKey, date, region) {
  const kDate = await hmacSha256("AWS4" + secretKey, date);
  const kRegion = await hmacSha256(kDate, region);
  const KService = await hmacSha256(kRegion, "s3");
  const kSigning = await hmacSha256(KService, "aws4_request");
  return kSigning;
}

const singingKey = await createSigningKey(SECRET_ACCESS_KEY, AMZ_DATE, REGION);
const signature = await hmacSha256(singingKey, base64EncodedPolicy);

function arrayBufferToHex(buffer) {
  const byteArray = new Uint8Array(buffer);
  const hexCodes = [...byteArray].map((byte) => {
    const hex = byte.toString(16);
    return hex.padStart(2, "0");
  });

  return hexCodes.join("");
}

console.log("signatureHex: ", signature);
console.log("signatureHex: ", arrayBufferToHex(signature));
