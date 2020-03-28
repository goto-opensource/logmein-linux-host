#!/usr/bin/env node

var http = require('http'),
    httpProxy = require('http-proxy'),
    express = require('express'),
    cookieParser = require('cookie-parser'),
    crypto = require('crypto'),
    path = require('path'),
    tcpPortUsed = require('tcp-port-used');

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
var termProxy = httpProxy.createProxyServer({ target: 'http://localhost:23821', ssl: false, changeOrigin: false });
var xtermProxy = httpProxy.createProxyServer({ target: 'http://localhost:23822', ssl: false, changeOrigin: false });
var rcLoginProxy = httpProxy.createProxyServer({ target: 'http://localhost:23823', ssl: false, changeOrigin: false });
var rcProxy = httpProxy.createProxyServer({ target: 'http://localhost:23825', ssl: false, changeOrigin: false });

app.use('/', express.static(path.join(__dirname, 'public')));

app.get('/term*', function(req, res) {
  console.log("GET request for term", req.url);
  termProxy.web(req, res, {});
});
app.post('/term*', function(req, res) {
  console.log("POST request for term", req.url);
  termProxy.web(req, res, {});
});
app.get('/xterm*', function(req, res) {
  console.log("GET request for xterm", req.url);
  xtermProxy.web(req, res, {});
});
app.post('/xterm*', function(req, res) {
  console.log("POST request for xterm", req.url);
  xtermProxy.web(req, res, {});
});
app.get('/*', function(req, res) {
  console.log("GET request for remctrl", req.url);
  tcpPortUsed.check(23826, "127.0.0.1")
  .then(function(inUse) {
    if (inUse) {
      rcProxy.web(req, res, {});
    }
    else {
      console.log("Failback to login proxy");
      res.header("login-proxy", 1);
      rcLoginProxy.web(req, res, {});
    }
  });
});
app.post('/*', function(req, res) {
  console.log("POST request for remctrl", req.url);
  rcProxy.web(req, res, {}, function(err) {
    rcLoginProxy.web(req, res, {});
  });
});

server.on('upgrade', function (req, socket, head) {
  if (req.url.match(/^\/term.*$/)) {
    console.log("Upgrade request for term", req.url);
    termProxy.ws(req, socket, head);
  }
  else if (req.url.match(/^\/xterm.*$/)) {
    console.log("Upgrade request for xterm", req.url);
    xtermProxy.ws(req, socket, head);
  } else {
    tcpPortUsed.check(23826, "127.0.0.1")
    .then(function(inUse) {
      if (inUse) {
        console.log("Upgrade request for remctrl (rc)", req.url);
        rcProxy.ws(req, socket, head); 
      } 
      else {
        console.log("Upgrade request for remctrl (login rc)", req.url);
        rcLoginProxy.ws(req, socket, head);
      }
    });
  }
});

server.listen(23820);
