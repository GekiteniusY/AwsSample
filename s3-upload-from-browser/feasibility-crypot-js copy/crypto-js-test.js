// バケット、リクエスト先の設定
const REGION = "ap-northeast-1";
const BUCKET_NAME = "s3-upload-from-browser-test";
const BUCKET_ACL = "public-read-write";
const REQUEST_URL = `https://${BUCKET_NAME}.s3.amazonaws.com/`;

// 使用するAWSの認証情報
const IAM_ACCESS_KEY_ID = "XXXXXXXXXXX";
const IAM_SECRET_ACCESS_KEY = "XXXXXXXXXXXXXXXXXXXXXX";

// HTML要素のID
const FORM_ID = "uploadForm";
const INPUT_ID = "fileInput";

document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById(FORM_ID);

  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    const fileInput = document.getElementById(INPUT_ID);
    const file = fileInput.files[0];
    const fileName = file.name;
    const fileKey = `/uploadFile/${fileName}`;

    const formData = await createBaseFormData();

    await uploadFileToS3(file, fileKey, formData);
  });
});

/**
 *
 * @returns
 */
async function createBaseFormData() {
  const encryptionType = "AES256";
  const encryptionAlgorithm = "AWS4-HMAC-SHA256";

  // Example
  // requestDate "2024-06-02T22:00:00.000Z"
  // requestDateYYYYMMDD: 20240602
  // amzRequestDate: 20240602T220000Z
  const requestDate = new Date();
  const requestDateYYYYMMDD = requestDate
    .toISOString()
    .slice(0, 10)
    .replace(/-/g, "");
  const amzRequestDate = requestDate.toISOString().replace(/-|:|\.\d\d\d/g, "");

  // 有効期限：リクエスト日時＋10分
  const expDuration = 10;
  const expirationDateString = new Date(
    requestDate.getTime() + expDuration * 60 * 1000
  ).toISOString();
  console.log(expirationDateString);

  const policyObject = {
    expiration: expirationDateString,
    conditions: [
      { bucket: BUCKET_NAME },
      // { acl: BUCKET_ACL },
      { "x-amz-server-side-encryption": encryptionType },
      {
        "x-amz-credential": `${IAM_ACCESS_KEY_ID}/${requestDateYYYYMMDD}/${REGION}/s3/aws4_request`,
      },
      { "x-amz-algorithm": encryptionAlgorithm },
      { "x-amz-date": amzRequestDate },
    ],
  };

  const signingKey = createSigningKey(
    IAM_SECRET_ACCESS_KEY,
    requestDateYYYYMMDD,
    REGION
  );
  // base64EncodedPolicy = StringToSign in signature calculation
  const base64EncodedPolicy = encodePolicyToBase64(policyObject);
  const signature = CryptoJS.HmacSHA256(base64EncodedPolicy, signingKey);

  // FormDataの作成
  const baseFormData = new FormData();
  // formData.set("acl", ACL);
  baseFormData.set("policy", base64EncodedPolicy);
  baseFormData.set("x-amz-algorithm", encryptionAlgorithm);
  baseFormData.set("x-amz-server-side-encryption", encryptionType);
  baseFormData.set("x-amz-signature", signature);
  baseFormData.set("x-amz-date", requestDateYYYYMMDD);

  return baseFormData;
}

/**
 *
 * @param {*} file
 * @param {*} fileKey
 * @param {*} formData
 */
async function uploadFileToS3(file, fileKey, formData) {
  if (file === null) {
    throw new Error("file is null");
  }

  if (fileKey === null) {
    throw new Error("fileKey is null");
  }

  if (formData === null) {
    throw new Error("formDate is null");
  }

  // Timeout Setting
  const TIMEOUT_DURATION = 10000; // 10秒
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, TIMEOUT_DURATION);

  // 送信するFormDataにファイル名とファイルをセット
  formData.set("file", file);
  formData.set("key", fileKey);
  // formData.set("Content-Type", "text/xml"); // コンテンツタイプの指定

  try {
    // TODO: 204が返ってくる？
    const response = await fetch(REQUEST_URL, {
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

/**
 *
 * @param {*} secretKey
 * @param {*} date
 * @param {*} region
 * @returns
 */
function createSigningKey(secretKey, date, region) {
  const kDate = CryptoJS.HmacSHA256(date, "AWS4" + secretKey);
  const kRegion = CryptoJS.HmacSHA256(region, kDate);
  const kService = CryptoJS.HmacSHA256("s3", kRegion);
  const kSigning = CryptoJS.HmacSHA256("aws4_request", kService);
  return kSigning;
}

/**
 *
 * @param {*} policyObject
 * @returns
 */
function encodePolicyToBase64(policyObject) {
  const policyString = createPolicyString(policyObject);
  return btoa(policyString);
}

/**
 *
 * @param {*} policyObject
 * @returns
 */
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
