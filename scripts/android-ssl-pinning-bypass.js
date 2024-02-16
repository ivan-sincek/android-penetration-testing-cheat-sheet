/************************************************************************
 * Name: Android SSL Pinning Bypass
 * OS: Android
 * Author: pcipolloni (Credits to the author!)
 * Source: https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida
 * Edited: https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/scripts/android-ssl-pinning-bypass.js
 * Extras: adb push cacert.der /data/local/tmp/cacert.der
 ************************************************************************/
setTimeout(function() {
	Java.perform(function() {
		var FileInputStream = Java.use("java.io.FileInputStream");
		var BufferedInputStream = Java.use("java.io.BufferedInputStream");
		var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
		var X509Certificate = Java.use("java.security.cert.X509Certificate");
		var KeyStore = Java.use("java.security.KeyStore");
		var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
		var SSLContext = Java.use("javax.net.ssl.SSLContext");

		var certificate = "/data/local/tmp/cacert.der";

		console.log("[>] Android SSL Pinning Bypass");
		console.log("[+] Loading CA...");
		var ca = null;
		var fileInputStream = null;
		var bufferedInputStream = null;
		try {
			fileInputStream = FileInputStream.$new(certificate);
			bufferedInputStream = BufferedInputStream.$new(fileInputStream);
			ca = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);
		} catch (error) {
			console.log("[X] " + error);
		} finally {
			if (fileInputStream !== null) {
				fileInputStream.close();
			}
			if (bufferedInputStream !== null) {
				bufferedInputStream.close();
			}
		}
		if (ca !== null) {
			console.log("[>] CA Info: " + Java.cast(ca, X509Certificate).getSubjectDN());

			console.log("[+] Creating KeyStore...");
			var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);
			keyStore.setCertificateEntry("ca", ca);

			console.log("[+] Creating TrustManager...");
			var trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManager.init(keyStore);

			console.log("[>] Hijacking SSLContext methods...");
			console.log("[>] Waiting for the application to invoke SSLContext.init()...");

			SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a, b, c) {
				console.log("[>] Application invoked SSLContext.init()!");
				SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, trustManager.getTrustManagers(), c);
				console.log("[+] SSLContext.init() has been initialized with a custom TrustManager!");
			};
		}
	});
}, 0);
