#secure-log-data [![npm version](https://badge.fury.io/js/%40debitoor%2Fsecure-log-data.svg)](https://badge.fury.io/js/%40debitoor%2Fsecure-log-data) [![Build Status](https://travis-ci.org/debitoor/secure-log-data.svg?branch=master)](https://travis-ci.org/debitoor/secure-log-data) [![Coverage Status](https://coveralls.io/repos/github/debitoor/secure-log-data/badge.svg?branch=master)](https://coveralls.io/github/debitoor/secure-log-data?branch=master) [![NSP Status](https://nodesecurity.io/orgs/debitoor/projects/9bc3c7f9-14fe-4040-9c15-3cb8715e7007/badge)](https://nodesecurity.io/orgs/debitoor/projects/9bc3c7f9-14fe-4040-9c15-3cb8715e7007)
Module for securing sensitive data from log objects.

##Installation

`npm i -S -E @debitoor/secure-log-data`

##Usage

```javascript
const secureLogData = require('@debitoor/secure-log-data');
const securedLogObject = securedLogObject(logObject);

```