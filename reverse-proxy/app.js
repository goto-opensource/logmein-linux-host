#!/usr/bin/env node

var http = require('http'),
    httpProxy = require('http-proxy'),
    express = require('express'),
    cookieParser = require('cookie-parser'),
    crypto = require('crypto'),
    path = require('path');

httpProxy.prototype.onError = function (err) {
  console.error("Error during connection:", err.code);
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
  proxy1.web(req, res, {});
});
app.post('/term*', function(req, res) {
  console.log("POST request for term", req.url);
  proxy1.web(req, res, {});
});
app.get('/xterm*', function(req, res) {
  console.log("GET request for xterm", req.url);
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
