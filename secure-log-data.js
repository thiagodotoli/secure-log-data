const traverse = require('traverse');

const SENSATIVE = [
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

const TOKEN = /token=[^;]*/;
const TOKEN_ENC = /token%3[^&]*/;

function sanitize(val) {
	if (!this.isLeaf || !val) {
		return;
	} else if (
		schemaError(this.key, this.parent && this.parent.node) ||
		SENSATIVE.indexOf(this.key.toLowerCase()) !== -1) {
		this.update('***');
	} else if (TOKEN.test(val)) {
		this.update(val.replace(TOKEN, 'token=***'));
	} else if (TOKEN_ENC.test(val)) {
		this.update(val.replace(TOKEN_ENC, 'token%3***'));
	}
}

function schemaError(key, obj) {
	return key === 'value' &&
		obj &&
		obj.message &&
		typeof obj.property === 'string' &&
		SENSATIVE.indexOf(obj.property.toLowerCase()) !== -1;
}

module.exports = function(data) {
	return traverse(data).map(sanitize);
};