# ブラウザからS3へのファイルアップロード

## AWS SDK V3(JavaScript)を使用するパターン
ブラウザでAWS SDK V3を利用する場合はwebpackを利用して事前にSDKをビルドしておく必要があります。

手順
1. npmなどで使用するAWSサービスのSDKをnpm installでローカルにダウンロードする（node_moduleフォルダ内にもってくる）。
2. 「ビルド元のJavaScriptファイル」を作成して、使用するインターフェイスをAWS SDKからimportする。
3. webpackのビルド設定を行う
4. webpackでビルドする
5. AWS SDKを使用したいJavaScriptで、webpackのビルドで生成したファイルからAWS SDKのインターフェイスをimportする




## 署名付きURLを使用するパターン




