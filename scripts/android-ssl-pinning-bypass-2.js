/************************************************************************
* Name: Android SSL Pinning Bypass 2
* OS: Android
* Author: sowdust (Credits to the author!)
* Source: https://codeshare.frida.re/@sowdust/universal-android-ssl-pinning-bypass-2
* Edited: https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/scripts/android-ssl-pinning-bypass-2.js
************************************************************************/
setTimeout(function() {
	Java.perform(function() {
		var ArrayList = Java.use("java.util.ArrayList");
		var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
		console.log("Running Android SSL Pinning Bypass...");
		TrustManagerImpl.checkTrustedRecursive.implementation = function(a, b, c, d, e, f) {
			return ArrayList.$new();
		}
	});
}, 0);
