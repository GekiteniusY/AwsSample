document.addEventListener("DOMContentLoaded", function () {
  const dropArea = document.getElementById("drop-area");

  ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
    dropArea.addEventListener(eventName, preventDefaults, false);
  });

  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  ["dragenter", "dragover"].forEach((eventName) => {
    dropArea.addEventListener(eventName, highlight, false);
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropArea.addEventListener(eventName, unhighlight, false);
  });

  function highlight() {
    dropArea.classList.add("highlight");
  }

  function unhighlight() {
    dropArea.classList.remove("highlight");
  }

  dropArea.addEventListener("drop", handleDrop, false);

  function handleDrop(e) {
    let dt = e.dataTransfer;
    let files = dt.files;
    handleFiles(files);
  }

  function handleFiles(files) {
    [...files].forEach(uploadFile);
  }

  function uploadFile(file) {
    let li = document.createElement("li");
    li.textContent = file.name;
    document.getElementById("file-list").appendChild(li);
    // ここでファイルをサーバーにアップロードする処理を追加する場合
    // uploadFileToServer(file);
  }
});
