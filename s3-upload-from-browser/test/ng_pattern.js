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
  return btoa(policyString);
}

const policyString = createPolicyString(policyObject);
console.log(policyString);
const base64EncodedPolicy = encodePolicyToBase64(policyObject);
console.log(base64EncodedPolicy);

// ========================================================================

const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const DATE = new Date("2015-12-29T00:00:00.000Z");
// CHECK: つまづきポイント
const AMZ_DATE = DATE.toISOString().slice(0, 10).replace(/-/g, "");
console.log("AMZ_DATE: ", AMZ_DATE);
const REGION = "us-east-1";

// ========================================================================

async function hmacSha256(key, msg) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const message = encoder.encode(msg);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, message);
  return signature; // ArrayBufferを直接返す
}

async function createSigningKey(secretKey, date, region) {
  // kDateまでは計算結果が合う7db2090321aa187aa0f1a82253d0b901e0fc85109ad025b356a2521ffb06471d
  const kDate = await hmacSha256("AWS4" + secretKey, date);
  console.log("kDate (hex): ", arrayBufferToHex(kDate));
  // kRegionから計算結果が合わなくなる
  const kRegion = await hmacSha256(kDate, region);
  console.log("kRegion (hex): ", arrayBufferToHex(kRegion));
  const kService = await hmacSha256(kRegion, "s3");
  console.log("kService (hex): ", arrayBufferToHex(kService));
  const kSigning = await hmacSha256(kService, "aws4_request");
  console.log("kSigning (hex): ", arrayBufferToHex(kSigning));
  return kSigning;
}

// ArrayBufferをBase64に変換するヘルパー関数
function bufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const signingKey = await createSigningKey(SECRET_ACCESS_KEY, AMZ_DATE, REGION);
const signature = await hmacSha256(signingKey, base64EncodedPolicy);
console.log("signature: ", signature);
console.log("signatureHex: ", arrayBufferToHex(signature));
