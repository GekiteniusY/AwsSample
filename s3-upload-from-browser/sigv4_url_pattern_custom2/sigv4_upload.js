async function uploadFileUsingSigV4(file, fileName) {
  if (file === null) {
    throw new Error("file is null");
  }

  if (fileName === null) {
    throw new Error("fileName is null");
  }

  // アクセスキー, シークレットアクセスキーを設定
  // const ACCESS_KEY = "";
  // const SECRET_ACCESS_KEY = "";
  const ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
  const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

  const ACL = "public-read"; // 'private'も背徹底可能
  // const BUCKET = "your bucket name";
  // const REGION = "your region";
  const BUCKET = "sigv4examplebucket";
  const REGION = "us-east-1";

  const DATE = new Date();
  const AMZ_DATE = DATE.toISOString()
    .replace(/[:-]\.\d{3}/g, "")
    .split(".")[0];

  const yyyyMMdd = AMZ_DATE.substring(0, 8);
  const CREDENTIAL_SCOPE = `${yyyyMMdd}/${REGION}/s3/aws4_request`;

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

  //＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝ポリシーのBase64変換＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝

  // CRLF(キャリッジリターン)：\r\nでないとだめ
  // https://ja.stackoverflow.com/questions/12897/%E6%94%B9%E8%A1%8C%E3%81%AE-n%E3%81%A8-r-n%E3%81%AE%E9%81%95%E3%81%84%E3%81%AF%E4%BD%95%E3%81%A7%E3%81%99%E3%81%8B
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

  function encodePolicyToBase64(policyObject) {
    const policyString = createPolicyString(policyObject);
    return btoa(policyString);
  }

  const policyString = createPolicyString(policyObject);
  console.log(policyString);
  const base64EncodedPolicy = encodePolicyToBase64(policyObject);
  console.log(base64EncodedPolicy);

  //＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝ポリシーのBase64変換＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝

  const TIMEOUT_DURATION = 10000; // 10秒
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, TIMEOUT_DURATION);

  try {
    const policy = base64EncodedPolicy;
    const singingKey = await createSigningKey(
      SECRET_ACCESS_KEY,
      AMZ_DATE,
      REGION
    );
    const signature = await hmacSha256(singingKey, policy);

    const formData = new FormData();
    formData.set("acl", ACL);
    formData.set("policy", policy);
    formData.set("key", fileName);
    formData.set("file", file);
    formData.set("x-amz-algorithm", "AWS4-HMAC-SHA256");
    formData.set("Content-Type", "text/xml"); // コンテンツタイプの指定
    formData.set("x-amz-server-side-encryption", "AES256");
    formData.set("x-amz-signature", signature);
    formData.set("x-amz-date", AMZ_DATE);

    // TODO: 204が返ってくる？
    const response = await fetch("url", {
      method: "POST",
      body: formData,
      signal: abortController.signal,
    });

    console.log(response);

    crearTimeout(timeoutId);
  } catch (error) {
    crearTimeout(timeoutId);

    if (error.name === "AbortError") {
      console.error("fetch timed out", error);
    } else {
      console.error("error ocured", error);
    }
  }
}
