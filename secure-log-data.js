const traverse = require('traverse');

const SENSITIVE = [
	'x-credentials',
	'credentials',
	'authorization',
	'password',
	'pwd',
	'pass',
	'x-token',
	'token',
	'security_token'
];

// if the path is 'foo.bar.key' then put the following in the map:
// key: 'foo.bar'
const SENSATIVE_PATH = {
	user: 'auth'
};

const TOKEN = /token=[^;]*/;
const TOKEN_ENC = /token%3[^&]*/;

function sanitize({ sensitiveKeys = [] } = {}) {
	sensitiveKeys = sensitiveKeys.map(key => key.toLowerCase()).concat(SENSITIVE);
	return function (val) {
		if (!this.isLeaf || !val) {
			return;
		} else if (
			schemaError(this.key, this.parent && this.parent.node, sensitiveKeys) ||
			sensitiveKeys.indexOf(this.key.toLowerCase()) !== -1 ||
			isSensativePath(this.key, this.parent && this.parent.path)) {
			this.update('***');
		} else if (typeof val === 'string') {
			if (TOKEN.test(val)) {
				this.update(val.replace(TOKEN, 'token=***'));
			} else if (TOKEN_ENC.test(val)) {
				this.update(val.replace(TOKEN_ENC, 'token%3***'));
			}
		}
	};
}

function isSensativePath(key, path) {
	if (!SENSATIVE_PATH[key] || !path || path.length < 1) {
		return false;
	}
	const sensativePath = SENSATIVE_PATH[key];
	let partialPath;
	for (let i = path.length; i >= 0; i--) {
		const previousPath = partialPath ? `${partialPath}.` : '';
		if (`${previousPath}${path[i]}` === sensativePath) {
			return true;
		}
	}
	return false;
}

function schemaError(key, obj, sensitive) {
	return key === 'value' &&
		obj &&
		obj.message &&
		typeof obj.property === 'string' &&
		sensitive.indexOf(obj.property.toLowerCase()) !== -1;
}

module.exports = function(data, options = {}) {
	return traverse(data).map(sanitize(options));
};
