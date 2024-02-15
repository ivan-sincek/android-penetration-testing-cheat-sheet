/************************************************************************
 * Name: Android Intent Monitor
 * OS: Android
 * Author: ivan-sincek
 * Source: https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/scripts/android-intent-monitor.js
 ************************************************************************/
setTimeout(function() {
	Java.perform(function() {
	    console.log("");
		var Intent = Java.use("android.content.Intent");
		Intent.getData.implementation = function() {
			var action = this.getAction();
			if (action) {
				console.log("Action: " + action);
			}
			var uri = this.getScheme();
			if (uri) {
				console.log("URI: " + this.getData());
			}
			var type = this.getType();
			if (type) {
				console.log("Type: " + type);
			}
			var activity = this.getComponent();
			if (activity) {
				console.log("Activity: " + activity.getClassName());
			}
			console.log("--------------------");
			return this.getData();
		}
	});
}, 0);
