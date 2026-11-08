// Sign-in page: put the CSRF token in the form and show why the last attempt didn't work.
(function () {
  function cookie(name) {
    var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : "";
  }
  var csrf = document.getElementById("csrf");
  csrf.value = cookie("XSRF-TOKEN");
  document.getElementById("form").addEventListener("submit", function () { csrf.value = cookie("XSRF-TOKEN"); });

  var q = location.search, msg = document.getElementById("msg");
  var text = q.indexOf("locked") >= 0 ? "Too many failed sign-ins from your address. Try again in 15 minutes."
    : q.indexOf("error") >= 0 ? "Wrong username or password."
    : q.indexOf("out") >= 0 ? "You are signed out." : "";
  if (text) {
    msg.textContent = text;
    msg.classList.remove("hidden");
    if (q.indexOf("out") >= 0) msg.classList.add("ok");
  }
})();
