const http = require("http");
const fs = require("fs");
const path = require("path");

const hostname = "127.0.0.1";
const port = 3000;

const server = http.createServer((req, res) => {
  fs.readFile(
    path.join(__dirname, "sigv4_url_pattern_official/index.html"),
    (err, data) => {
      if (err) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain");
        res.end("エラーが発生しました");
      } else {
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/html");
        res.end(data);
      }
    }
  );
});

server.listen(port, hostname, () => {
  console.log(`サーバーが http://${hostname}:${port}/ で起動しました`);
});
