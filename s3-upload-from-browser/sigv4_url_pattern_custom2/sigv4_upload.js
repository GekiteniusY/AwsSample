async function uploadFileUsingSigV4(file, fileName) {
  if (file === null) {
    throw new Error("file is null");
  }

  if (fileName === null) {
    throw new Error("fileName is null");
  }

  // アクセスキー, シークレットアクセスキーを設定
  const ACCESS_KEY = "";
  const SECRET_ACCESS_KEY = "";

  const ACL = "public-read"; // 'private'も背徹底可能
  const BUCKET = "your bucket name";
  const REGION = "your region";

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

  // 署名用のポリシーを作成
  async function encodePolicy() {
    // ポリシーのオブジェクト
    const policy = {
      expiration: new Date(new Date().getTime() + 60 * 1000).toISOString(), // 現時点＋60秒を有効期限に設定
      conditions: [
        { acl: ACL },
        { bucket: BUCKET },
        { "x-amz-algorithm": "AWS4-HMAC-SHA256" },
        { "x-amz-credential": `${ACCESS_KEY}/${CREDENTIAL_SCOPE}` },
        { "x-amz-date": AMZ_DATE },
        { "x-amz-server-side-encryption": "AES256" },
      ],
    };

    const policyString = JSON.stringify(policy);
    const policyBase64 = btoa(policyString);

    return policyBase64;
  }

  const TIMEOUT_DURATION = 10000; // 10秒
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, TIMEOUT_DURATION);

  try {
    const policy = await encodePolicy();
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
