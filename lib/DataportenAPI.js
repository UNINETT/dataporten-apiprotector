"use strict";

var basicAuthParser = require('basic-auth-parser');

var DataportenAPIRequest = function(feideconnect, req, opts) {
	this.feideconnect = feideconnect;
	this.req = req;
	this.opts = opts;

	this.userid = null;
	this.useridsec = null;

	this.clientid = null;
	this.scopes = null;

	this.inited = false;
};

DataportenAPIRequest.prototype.init = function() {
	this.authenticatePlatform();
	this.parseHeaders();
	this.inited = true;
}

DataportenAPIRequest.prototype.parseHeaders = function() {

	if (this.req.headers['x-dataporten-userid']) {
		this.userid = this.req.headers['x-dataporten-userid'];
	}
	if (this.req.headers['x-dataporten-userid-sec']) {
		this.useridsec = this.req.headers['x-dataporten-userid-sec'].split(',');
	}
	if (this.req.headers['x-dataporten-scopes']) {
		this.scopes = this.req.headers['x-dataporten-scopes'].split(',');
	}
	if (this.req.headers['x-dataporten-clientid']) {
		this.clientid = this.req.headers['x-dataporten-clientid'];
	}
	if (this.req.headers['x-dataporten-accesstoken']) {
		this.accesstoken = this.req.headers['x-dataporten-token'];
	}
	// console.log(this);
	// console.log("Headers", JSON.stringify(this.req.headers, undefined, 3));

};


DataportenAPIRequest.prototype.hasUser = function() {
	return this.userid !== null;
}
DataportenAPIRequest.prototype.requireUser = function() {
	if (!this.hasUser()) {
		throw new Error("Request is required to be on behalf of an authenticated end user but is not.")
	}
}
DataportenAPIRequest.prototype.requireUserUnlessScopes = function(scopes) {
	if (!this.hasScopes(scopes)) {
		throw new Error("Request is required to be on behalf of an authenticated end user but is not. " +
			"This requirement is relaxed when request is authorized with the sufficient scopes");
	}
}



DataportenAPIRequest.prototype.hasScope = function(scope) {
	if (this.scopes === null) {
		return false;
	}
	for (var i = 0; i < this.scopes.length; i++) {
		if (this.scopes[i] === scope) {
			return true;
		}
	}
	return false;
}

DataportenAPIRequest.prototype.hasScopes = function(scopes) {
	for (var i = 0; i < scopes.length; i++) {
		if (!this.hasScope(scopes[i])) {
			return false;
		}
	}
	return true;
}

DataportenAPIRequest.prototype.requireScopes = function(scopes) {
	if (!this.hasScopes(scopes)) {
		throw new Error("Request is not authorized with all the required sub scopes");
	}
}


DataportenAPIRequest.prototype.authenticatePlatform = function() {

	var authHeader = this.req.get('Authorization');
	if (!authHeader) {
		throw new Error("Missing Authorization header");
	}

	var authParts = basicAuthParser(authHeader);
	var authOK = (authParts.scheme === 'Basic' && authParts.username === 'dataporten' &&
		authParts.password === this.feideconnect.config.password);

	if (!authOK) {
		// console.error("Request was not propertly authenticated from the Connect platform. Provided credentials was " + authParts.username + ":" + authParts.password)
		throw new Error("Request was not propertly authenticated from the Connect platform.")
	}

	// console.log("Parts", JSON.stringify(authParts, undefined, 2));
}



var DataportenAPI = function(config) {
	this.config = config;
};

DataportenAPI.prototype.cors = function() {
	return function(req, res, next) {
		res.header("Access-Control-Allow-Origin", "*");
		res.header("Access-Control-Allow-Methods", "GET, PUT, PATCH, POST, DELETE, OPTIONS");
		res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
		// console.log("Method is ", req.method);
		if (req.method === 'OPTIONS') {
			return res.sendStatus(204);
		}
		next();
	}
}

DataportenAPI.prototype.setup = function(opts) {
	var feideconnectapi = this;
	return function(req, res, next) {
		req.dataporten = new DataportenAPIRequest(feideconnectapi, req, opts);
		try {
			req.dataporten.init();
		} catch (err) {
			return res.status(500).json({
				"message": err.message
			});
		}

		next();
	};
}

DataportenAPI.prototype.policy = function(policy) {
	var that = this;
	return function(req, res, next) {

		if (!req.dataporten) {
			throw new Error("Dataporten needs to be setup before we can run a policy. Use the setup() middleware first.")
		}

		for (var key in policy) {

			if (policy[key] !== false) {

				switch (key) {
					case "requireUser":
						req.dataporten.requireUser();
						break;

					case "requireUserUnlessScopes":
						req.dataporten.requireUserUnlessScopes(policy[key]);
						break;

					case "requireScopes":
						req.dataporten.requireScopes(policy[key]);
						break;

					default:
						throw new Error("Cannot process unknown policy [" + key + "]");

				}
			}

		}

		next();
	};
}



exports.DataportenAPI = DataportenAPI;
