#!/usr/bin/env node

var http = require('http'),
    httpProxy = require('http-proxy'),
    express = require('express'),
    cookieParser = require('cookie-parser'),
    crypto = require('crypto'),
    path = require('path'),
    execSync = require('child_process').execSync;

httpProxy.prototype.onError = function (err) {
  console.error("Error during connection:", err.code);
}

function setCustomHeaders(res, term_name) {
  const snap_version = process.env.SNAP_VERSION || "develop"
  const snap_revision = process.env.SNAP_REVISION || "develop"
  const host_install_source = "snap"
  const os_name = "Linux"
  var os_arch = "unknown"
  try {
    os_arch = execSync("hostnamectl 2>/dev/null | awk -F': ' '/Architecture/ { print $2 } ' 2>/dev/null").toString().trim();
  }
  catch (e) {}
  var distro_version = "unknown"
  try {
    distro_version = execSync("hostnamectl 2>/dev/null | awk -F': ' '/Operating System/ { print $2 } ' 2>/dev/null").toString().trim();
  }
  catch (e) {}

  res.append("lmi-host-version", snap_version + " " + host_install_source + "." + snap_revision)
  res.append("lmi-term-name", term_name)
  res.append("lmi-os-name", os_name)
  res.append("lmi-os-arch", os_arch)
  res.append("lmi-os-version", distro_version)
}

var app = express();
var http = require('http');

app.use(cookieParser());

app.use(function (req, res, next) {
  var rasid = req.cookies['RASID'];
  if (rasid === undefined) {
    console.log("Generating RASID");
    res.cookie("RASID", crypto.randomBytes(40).toString("hex"));
  }
  next();
});

var server = http.createServer(app);
var proxy1 = httpProxy.createProxyServer({ target: 'http://localhost:23821', ssl: false, changeOrigin: false });
var proxy2 = httpProxy.createProxyServer({ target: 'http://localhost:23822', ssl: false, changeOrigin: false });

app.get('/term*', function(req, res) {
  console.log("GET request for term", req.url);
  setCustomHeaders(res, "pytty");
  proxy1.web(req, res, {});
});
app.post('/term*', function(req, res) {
  console.log("POST request for term", req.url);
  proxy1.web(req, res, {});
});
app.get('/xterm*', function(req, res) {
  console.log("GET request for xterm", req.url);
  setCustomHeaders(res, "wetty");
  proxy2.web(req, res, {});
});
app.post('/xterm*', function(req, res) {
  console.log("POST request for xterm", req.url);
  proxy2.web(req, res, {});
});

server.on('upgrade', function (req, socket, head) {
  if (req.url.match(/^\/term.*$/)) {
    console.log("Upgrade request for term", req.url);
    proxy1.ws(req, socket, head);
  }
  else if (req.url.match(/^\/xterm.*$/)) {
    console.log("Upgrade request for xterm", req.url);
    proxy2.ws(req, socket, head);
  } else {
    console.log("Upgrade request for unknown app", req.url)
  }
});

app.use('/', express.static(path.join(__dirname, 'public')))

server.listen(23820);
