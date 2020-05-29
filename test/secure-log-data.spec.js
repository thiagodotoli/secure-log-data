const expect = require('chai').expect;
const secure = require('../secure-log-data');

describe('secure-data.spec.js', function() {

	it('should mask all x-credentials values', function() {
		expect(secure({
			headers: {
				'x-credentials': 'pwd=1',
				name: 'a'
			},
			inner: {
				name: 'b',
				data: {
					'x-credentials': 'pwd=2',
					user: 'bob'
				}
			}
		})).to.eql({
			headers: {
				'x-credentials': '***',
				name: 'a'
			},
			inner: {
				name: 'b',
				data: {
					'x-credentials': '***',
					user: 'bob'
				}
			}
		});
	});

	it('should mask passwords', function() {
		expect(secure({
			good: 1,
			password: 'ab',
			pwd: 'a',
			pass: 1,
			errors: [
				{
					message: 'has less length than allowed',
					value: 'thomas',
					type: 'string',
					property: 'password'
				},
				{
					message: 'invalid email',
					value: 'abu@debitoor.com',
					type: 'string',
					property: 'email'
				}]
		})).to.eql({
			good: 1,
			password: '***',
			pwd: '***',
			pass: '***',
			errors: [
				{
					message: 'has less length than allowed',
					value: '***',
					type: 'string',
					property: 'password'
				},
				{
					message: 'invalid email',
					value: 'abu@debitoor.com',
					type: 'string',
					property: 'email'
				}]
		});
	});

	it('should mask all tokens', function() {
		expect(secure({
			cookie: 'newrelic=1;token=123;x-code=23;ko=yes',
			inner: {
				name: 'b',
				data: {
					cookie: 'a=1;token=1',
					items: [1, 2, {a: 1}]
				}
			},
			url: '/pdf?url=https%3A%2F%2Fapp.debitoor.com%2Fprintify.html%23%2Finvoice%2F57e7d6ff2b3eba10001b6fd3%3Ftoken%312345&zoom=1',
			query: {
				url: 'https://app.debitoor.com/printify.html#/invoice/57e7d6ff2b3eba10001b6fd3?token=eyJ2c2VyIjoiNTM5NmYxZDdhOGYxOWY2ODViODdiYjUyIiwicm9sZSI6InVzZXIiLCJyZWZlcnJlciI6ImRlYml0b29yLmNvbSIsIiRlIjowfQorwqfCmR4Kwo7CuUccwokiPsOswqc4Ug'
			}
		})).to.eql({
			cookie: 'newrelic=1;token=***;x-code=23;ko=yes',
			inner: {
				name: 'b',
				data: {
					cookie: 'a=1;token=***',
					items: [1, 2, {a: 1}]
				}
			},
			url: '/pdf?url=https%3A%2F%2Fapp.debitoor.com%2Fprintify.html%23%2Finvoice%2F57e7d6ff2b3eba10001b6fd3%3Ftoken%3***&zoom=1',
			query: {
				url: 'https://app.debitoor.com/printify.html#/invoice/57e7d6ff2b3eba10001b6fd3?token=***'
			}
		});
	});

	it('should mask all sensative paths', function() {
		expect(secure({
			auth: {
				user: 'secretUserName',
				good: 'not secret'
			},
			authX: {
				user: 'not secret',
				good: 'not secret'
			},
			user: {
				auth: 'not secret'
			},
			data: {
				auth: {
					user: 'secretUserName',
					good: 'not secret'
				}
			},
			datas: [
				{
					auth: {
						user: 'secretUserName',
						good: 'not secret'
					}
				},
				{
					data: {
						auth: {
							user: 'secretUserName',
							good: 'not secret'
						}
					}
				}
			]
		})).to.eql({
			auth: {
				user: '***',
				good: 'not secret'
			},
			authX: {
				user: 'not secret',
				good: 'not secret'
			},
			user: {
				auth: 'not secret'
			},
			data: {
				auth: {
					user: '***',
					good: 'not secret'
				}
			},
			datas: [
				{
					auth: {
						user: '***',
						good: 'not secret'
					}
				},
				{
					data: {
						auth: {
							user: '***',
							good: 'not secret'
						}
					}
				}
			]
		});
	});

	it('should hide custom sensitive data', () => {
		expect(secure({
			headers: {
				'mySensitiveField': 'pwd=1',
				'x-credentials': 'pwd=1',
				name: 'a'
			},
			inner: {
				name: 'b',
				data: {
					'mySensitiveField': 'pwd=2',
					'x-credentials': 'pwd=1',
					user: 'bob'
				}
			}
		}, { sensitiveKeys: ['mySensitiveField'] })).to.eql({
			headers: {
				'mySensitiveField': '***',
				'x-credentials': '***',
				name: 'a'
			},
			inner: {
				name: 'b',
				data: {
					'mySensitiveField': '***',
					'x-credentials': '***',
					user: 'bob'
				}
			}
		});
	});

});
