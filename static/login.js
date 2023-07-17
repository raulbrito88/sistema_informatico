document.addEventListener("DOMContentLoaded", function() {
    var browser = bowser.getParser(window.navigator.userAgent);
    var browserName = browser.getBrowserName();
    console.log("Nombre del navegador: " + browserName);
  });
  