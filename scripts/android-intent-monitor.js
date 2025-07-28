/************************************************************************
 * Name: Android Intent Monitor
 * OS: Android
 * Author: ivan-sincek
 * Source: https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/scripts/android-intent-monitor.js
 ************************************************************************/
function hook(intent) {
	var text = [];
	var tmp = null;
	tmp = intent.getComponent();
	if (tmp) {
		text.push("Package Name: " + tmp.getPackageName());
		text.push("Class Name: " + tmp.getClassName());
	}
	tmp = intent.getData();
	if (tmp) {
		text.push("URI: " + tmp);
	}
	tmp = intent.getAction();
	if (tmp) {
		text.push("Action: " + tmp);
	}
	tmp = intent.getFlags();
	if (tmp) {
		text.push("Flags: " + tmp);
	}
	tmp = intent.getType();
	if (tmp) {
		text.push("Type: " + tmp);
	}
	tmp = intent.getExtras();
	if (tmp) {
		var keys = tmp.keySet().iterator();
		while (keys.hasNext()) {
			var type = "null";
			var value = "null";
			var key = keys.next();
			var obj = tmp.get(key);
			if (obj) {
				try {
					type = obj.getClass().getSimpleName();
					value = (obj.getClass().isArray() ? Java.use("org.json.JSONArray").$new(obj) : obj).toString();
				} catch (error) {
					value = error.toString();
				}
			}
			text.push("Extra \"" + key + "\" (" + type + "): " + value);
		}
	}
	text.push("--------------------");
	console.log(text.join("\n"));
}
function hookGetData() {
	hook(this);
	return this.getData();
}
function hookGetIntent() {
	var intent = this.getIntent();
	hook(intent);
	return intent;
}
setTimeout(function() {
	Java.perform(function() {
		console.log("");
		var Intent = Java.use("android.content.Intent");
		Intent.getData.implementation = hookGetData;
		// var Activity = Java.use("android.app.Activity");
		// Activity.getIntent.implementation = hookGetIntent;
	});
}, 0);
