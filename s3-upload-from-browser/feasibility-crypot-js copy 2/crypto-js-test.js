// アップロード先のS3の設定情報
const REGION = "ap-northeast-1";
const BUCKET_NAME = "s3-upload-from-browser-test";
const FOLDER_PATH = "UploadFile/";
const BUCKET_ACL = "public-read-write";
const REQUEST_URL = `https://${BUCKET_NAME}.s3.amazonaws.com/`;

// 使用するAWSの認証情報
const IAM_ACCESS_KEY_ID = "XXXXXXXXXXX";
const IAM_SECRET_ACCESS_KEY = "XXXXXXXXXXXXXXXXXXXXXX";

// HTML要素のID情報
const FORM_ID = "uploadForm";
const INPUT_ID = "fileInput";

document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("uploadForm"); // フォームのIDを指定

  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    // アップロード対象のファイル情報を取得
    const fileInput = document.getElementById(INPUT_ID);
    const file = fileInput.files[0];

    if (file === undefined || file === null) {
      console.log("file is undefined or null");
      return;
    }

    const fileInfo = {
      file: file,
      fileKey: FOLDER_PATH + file.name,
      mimeType: file.type,
    };

    // アップロードに使用するFormDataオブジェクトの生成
    const formData = createFormData(fileInfo);

    // アップロード
    uploadFileToS3(formData);
  });
});

/**
 *
 * @param {*} formData
 */
async function uploadFileToS3(formData) {
  if (formData === null) {
    throw new Error("formDate is null");
  }

  // Timeout Setting
  const TIMEOUT_DURATION = 20000; // 10秒
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, TIMEOUT_DURATION);

  try {
    // 204のレスポンスが返ってくるとアップロード成功
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
 * @param {*} fileInfo
 * @returns
 */
function createFormData(fileInfo) {
  if (fileInfo === null || Object.keys(fileInfo).length != 3) {
    throw new Error("fileInfo is null or has not enough info");
  } else if (
    !fileInfo.hasOwnProperty("file") ||
    !fileInfo.hasOwnProperty("fileKey") ||
    !fileInfo.hasOwnProperty("mimeType")
  ) {
    throw new Error("fileInfo must have file, fileKey and mimeType");
  }

  const certificateInfo = createCertificateInfo();

  // どの順番でsetするかでリクエストの成否が変わるので注意
  const formData = new FormData();
  // ファイルとファイル名をセット
  formData.set("key", fileInfo.fileKey);
  formData.set("file", fileInfo.file);
  formData.set("Content-Type", fileInfo.mimeType);
  // ポリシーなどの必要な情報をセット
  formData.set("policy", certificateInfo.policy);
  formData.set("x-amz-algorithm", certificateInfo.amzAlgorizm);
  formData.set(
    "x-amz-server-side-encryption",
    certificateInfo.amzServerSideEncryption
  );
  formData.set("x-amz-signature", certificateInfo.signature);
  formData.set("x-amz-date", certificateInfo.amzDate);
  // こちらは順番未確認
  // formData.set("acl", certificateInfo.acl);

  return formData;
}

/**
 *
 * @returns
 */
function createCertificateInfo() {
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
  const amzRequestDate = requestDate.toISOString().replace(/-|:|\.\d\d\d/g, ""); // ハイフン、コロンとミリ秒を削除

  // 有効期限：リクエスト日時＋10分
  const expDuration = 10;
  // Stringにしないとエラーになる
  const expirationDateString = new Date(
    requestDate.getTime() + expDuration * 60 * 1000
  ).toISOString();

  const policyObject = {
    expiration: expirationDateString,
    conditions: [
      { bucket: `${BUCKET_NAME}` },
      // { acl: `${ACL}` },
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
  // base64EncodedPolicy = signatureの計算に使用されるStringToSign
  const base64EncodedPolicy = encodePolicyToBase64(policyObject);
  const signature = CryptoJS.HmacSHA256(base64EncodedPolicy, signingKey);

  return {
    policy: base64EncodedPolicy,
    signature: signature,
    amzAlgorizm: encryptionAlgorithm,
    amzServerSideEncryption: encryptionType,
    amzDate: requestDateYYYYMMDD,
    acl: BUCKET_ACL,
  };
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
