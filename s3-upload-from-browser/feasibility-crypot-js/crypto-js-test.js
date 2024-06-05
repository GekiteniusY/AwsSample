const BUCKET = "s3-upload-from-browser-test";
const REGION = "ap-northeast-1";
const IAM_ACCESS_KEY_ID = "XXXXXXXXXXX";
const IAM_SECRET_ACCESS_KEY = "XXXXXXXXXXXXXXXXXXXXXX";
const ACL = "public-read-write";

const REQUEST_DATE = new Date("2024-06-02T22:00:00.000Z");
// AMZ_DATE: 20240602
const AMZ_REQUEST_DATE = REQUEST_DATE.toISOString()
  .slice(0, 10)
  .replace(/-/g, "");

const policyObject = {
  expiration: "2024-06-10T12:00:00.000Z",
  conditions: [
    { bucket: `${BUCKET_NAME}` },
    // { acl: `${ACL}` },
    { "x-amz-server-side-encryption": "AES256" },
    {
      "x-amz-credential": `${IAM_ACCESS_KEY_ID}/${AMZ_REQUEST_DATE}/${REGION}/s3/aws4_request`,
    },
    { "x-amz-algorithm": "AWS4-HMAC-SHA256" },
    // TODO: Check
    { "x-amz-date": "20240602T220000Z" },
  ],
};

// const policyString = createPolicyString(policyObject);

const signingKey = createSigningKey(
  IAM_SECRET_ACCESS_KEY,
  AMZ_REQUEST_DATE,
  REGION
);
const base64EncodedPolicy = encodePolicyToBase64(policyObject);
const signature = CryptoJS.HmacSHA256(base64EncodedPolicy, signingKey);

function createSigningKey(secretKey, date, region) {
  const kDate = CryptoJS.HmacSHA256(date, "AWS4" + secretKey);
  const kRegion = CryptoJS.HmacSHA256(region, kDate);
  const kService = CryptoJS.HmacSHA256("s3", kRegion);
  const kSigning = CryptoJS.HmacSHA256("aws4_request", kService);
  return kSigning;
}

function encodePolicyToBase64(policyObject) {
  const policyString = createPolicyString(policyObject);
  return btoa(policyString);
}

document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("uploadForm"); // フォームのIDを指定

  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    var fileInput = document.getElementById("fileInput");
    var file = fileInput.files[0];

    uploadFileToS3(file, "test");
  });
});

async function uploadFileToS3(file, fileName) {
  if (file === null) {
    throw new Error("file is null");
  }

  if (fileName === null) {
    throw new Error("fileName is null");
  }

  const TIMEOUT_DURATION = 20000; // 10秒
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, TIMEOUT_DURATION);

  try {
    const formData = new FormData();
    // formData.set("acl", ACL);
    formData.set("policy", base64EncodedPolicy);
    formData.set("key", fileName);
    formData.set("file", file);
    formData.set("x-amz-algorithm", "AWS4-HMAC-SHA256");
    // formData.set("Content-Type", "text/xml"); // コンテンツタイプの指定
    formData.set("x-amz-server-side-encryption", "AES256");
    formData.set("x-amz-signature", signature);
    formData.set("x-amz-date", AMZ_REQUEST_DATE);

    // TODO: 204が返ってくる？
    const response = await fetch(`https://${BUCKET_NAME}.s3.amazonaws.com/`, {
      method: "POST",
      body: formData,
      signal: abortController.signal,
    });

    console.log(response);
  } catch (error) {
    if (error.name === "AbortError") {
      console.error("fetch timed out", error);
    } else {
      console.error("error ocured", error);
    }
  }
}

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
