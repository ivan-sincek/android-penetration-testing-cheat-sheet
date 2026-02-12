/************************************************************************
 * Name: Android Intent Monitor
 * OS: Android
 * Author: ivan-sincek
 * Source: https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/scripts/android-intent-monitor.js
 ************************************************************************/
function dumpIntent(intent) {
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
	dumpIntent(this);
	return this.getData();
}
function hookGetIntent() {
	var intent = this.getIntent();
	dumpIntent(intent);
	return intent;
}
function hookSetResult1(code) {
	var text = [];
	text.push("Result Activity: " + this.getClass().getName());
	text.push("Result Code: " + code);
	text.push("--------------------");
	console.log(text.join("\n"));
	return this.setResult(code);
}
function hookSetResult2(code, intent) {
	var text = [];
	text.push("Result Activity: " + this.getClass().getName());
	text.push("Result Code: " + code);
	if (intent) {
		console.log(text.join("\n"));
		dumpIntent(intent);
	} else {
		text.push("--------------------");
		console.log(text.join("\n"));
	}
	return this.setResult(code, intent);
}
setTimeout(function() {
	Java.perform(function() {
		console.log("");
		// DEEP LINKS
		// var Intent = Java.use("android.content.Intent");
		// Intent.getData.implementation = hookGetData;
		// INTENTS
		var Activity = Java.use("android.app.Activity");
		Activity.getIntent.implementation = hookGetIntent;
		// ACTIVITY RESULT CALLBACKS
		// Activity.setResult.overload("int").implementation = hookSetResult1;
		// Activity.setResult.overload("int", "android.content.Intent").implementation = hookSetResult2;
	});
}, 0);
