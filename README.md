# Android Penetration Testing Cheat Sheet

This is more of a checklist for myself. May contain useful tips and tricks. **Still need to add a lot of things.**

Everything was tested on Kali Linux v2023.1 (64-bit) and Samsung A5 (2017) with Android OS v8.0 (Oreo) and Magisk root v25.2.

Check [Magisk](https://topjohnwu.github.io/Magisk) if you wish to root your Android device. I have no [liability](https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/LICENSE) over your actions.

For help with any of the tools type `<tool_name> [-h | -hh | --help]` or `man <tool_name>`.

If you didn't already, read [OWASP MSTG](https://github.com/OWASP/owasp-mastg) and [OWASP MASVS](https://github.com/OWASP/owasp-masvs). You can download OWASP MSTG checklist from [here](https://github.com/OWASP/owasp-mastg/releases).

Highly recommend reading [HackTricks - Android Applications Pentesting](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting).

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [nvd.nist.gov/vuln-metrics/cvss/v3-calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

My other cheat sheets:

* [iOS Testing Cheat Sheet](https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet)
* [Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/penetration-testing-cheat-sheet)
* [WiFi Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet)

Future plans:

* install Burp Proxy and ZAP certificates,
* test widgets, push notifications, and Firebase,
* deeplink hijacking, task hijacking, intent hijacking,
* intent provider injections, content provider injections, broadcast receiver injections,
* SMALI code injection,
* WebView attacks,
* create more Frida scripts.

## Table of Contents

**0. [Install Tools](#0-install-tools)**

* [WiFi ADB - Debug Over Air](#wifi-adb---debug-over-air)
* [Magisk Frida](#magisk-frida)
* [Magisk SQLite 3](#magisk-sqlite-3)
* [Kali Linux Tools](#kali-linux-tools)
* [Java](#java)
* [Apktool](#apktool)
* [Mobile Security Framework (MobSF)](#mobile-security-framework-mobsf)
* [Drozer](#drozer)

**1. [Basics](#1-basics)**

* [Android Debug Bridge (ADB)](#android-debug-bridge-adb)
* [Install/Uninstall an APK](#installuninstall-an-apk)
* [Download/Upload Files and Directories](#downloadupload-files-and-directories)
* [Bypassing Permission Denied](#bypassing-permission-denied)

**2. [Inspect an APK](#2-inspect-an-apk)**

* [Pull an APK (base.apk)](#pull-an-apk-baseapk)
* [AndroidManifest.xml](#androidmanifestxml)
* [strings.xml](#stringsxml)

**3. [Search for Files and Directories](#3-search-for-files-and-directories)**

* [SharedPreferences](#sharedpreferences)

**4. [Inspect Files](#4-inspect-files)**

* [Single File](#single-file)
* [Multiple Files](#multiple-files)
* [File Scraper](#file-scraper)
* [SQLite 3](#sqlite-3)
* [Nuclei](#nuclei)
* [Backups](#backups)

**5. [Deeplinks](#5-deeplinks)**

**6. [Frida](#6-frida)**

* [Frida Scripts](#frida-scripts)

**7. [Objection](#7-objection)**

* [Bypasses](#bypasses)

**8. [Drozer](#8-drozer)**

* [Activities](#activities)
* [Providers](#providers)
* [Broadcast Receivers](#broadcast-receivers)

**9. [Decompile an APK](#9-decompile-an-apk)**

**10. [Repackage an APK](#10-repackage-an-apk)**

* [Decode](#decode)
* [Repackage](#repackage)
* [Code Sign](#code-sign)

**11. [Miscellaneous](#11-miscellaneous)**

* [Monitor the System Log](#monitor-the-system-log)
* [Monitor File Changes](#monitor-file-changes)

**12. [Tips and Security Best Practices](#12-tips-and-security-best-practices)**

**13. [Useful Websites and Tools](#13-useful-websites-and-tools)**

## 0. Install Tools

### WiFi ADB - Debug Over Air

Install [WiFi ADB - Debug Over Air](https://play.google.com/store/apps/details?id=com.ttxapps.wifiadb). To be used with [ADB](#android-debug-bridge-adb).

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/wifi_adb.jpg" alt="WiFi ADB - Debug Over Air" height="600em"></p>

<p align="center">Figure 1 - WiFi ADB - Debug Over Air</p>

### Magisk Frida

Download [Magisk Frida](https://github.com/ViRb3/magisk-frida/releases), then, open your [Magisk](https://topjohnwu.github.io/Magisk) app and install Frida by importing the downloaded archive.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/magisk_install_from_storage.jpg" alt="Magisk Frida" height="600em"></p>

<p align="center">Figure 2 - Magisk Frida</p>

### Magisk SQLite 3

Download [Magisk SQLite 3](https://github.com/stylemessiah/SQLite3UniversalBinaries/tags), then, open your [Magisk](https://topjohnwu.github.io/Magisk) app and install SQLite 3 by importing the downloaded archive.

### Kali Linux Tools

Install required tools on your Kali Linux:

```fundamental
apt-get -y install docker.io

systemctl start docker

apt-get -y install adb dex2jar jadx nuclei radare2 sqlite3 sqlitebrowser xmlstarlet zipalign

pip3 install frida-tools objection file-scraper
```

More information about my tool can be found at [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

Make sure that Frida and Objection are always up to date:

```fundamental
pip3 install --upgrade frida-tools objection
```

### Java

Install:

```fundamental
apt-get -y install default-jdk
```

More Java/JDK versions can be found at [oracle.com/java/technologies/downloads/archive](https://www.oracle.com/java/technologies/downloads/archive).

To switch between multiple Java/JDK versions, run:

```fundamental
update-alternatives --config java

update-alternatives --config javac
```

### Apktool

Download and install:

```bash
apt-get -y install aapt

wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O apktool

chmod +x apktool && cp apktool /usr/local/bin/apktool

wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar -O apktool.jar

chmod +x apktool.jar && cp apktool.jar /usr/local/bin/apktool.jar
```

### Mobile Security Framework (MobSF)

Install:

```fundamental
docker pull opensecurity/mobile-security-framework-mobsf
```

Run:

```fundamental
docker run -it --rm --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

Navigate to `http://localhost:8000` using your preferred web browser.

Uninstall:

```fundamental
docker image rm opensecurity/mobile-security-framework-mobsf
```

### Drozer

Install:

```fundamental
docker pull fsecurelabs/drozer
```

Run:

```fundamental
docker run -it --rm --name drozer fsecurelabs/drozer
```

Download [Drozer Agent](https://github.com/WithSecureLabs/drozer-agent/releases) and install it either manually or by using [ADB](#android-debug-bridge-adb).

Uninstall:

```fundamental
docker image rm fsecurelabs/drozer
```

## 1. Basics

### Android Debug Bridge (ADB)

Start the server:

```fundamental
adb start-server
```

Stop the server:

```fundamental
adb kill-server
```

List attached devices:

```fundamental
adb devices
```

Connect to a remote device using [WiFi ADB](#wifi-adb---debug-over-air):

```fundamental
adb connect 192.168.1.10:5555
```

Open a system shell as non-root:

```fundamental
adb shell
```

Open a system shell as root:

```fundamental
adb shell su
```

### Install/Uninstall an APK

Install an APK (specify `-s` to install the APK to a removable storage):

```fundamental
adb install someapp.apk

adb install -s someapp.apk
```

Uninstall an APK (specify `-k` to keep the data and cache directories):

```fundamental
adb uninstall com.someapp.dev

adb uninstall -k com.someapp.dev
```

### Download/Upload Files and Directories

Some of the internal storage paths:

```fundamental
cd /data/local/tmp/

cd /data/data/com.someapp.dev/cache/
cd /data/user/0/com.someapp.dev/cache/

cd /mnt/sdcard/Android/data/com.someapp.dev/cache/
cd /storage/emulated/0/Android/data/com.someapp.dev/cache/

cd /mnt/sdcard/Android/obb/com.someapp.dev/cache/
cd /storage/emulated/0/Android/obb/com.someapp.dev/cache/

cd /mnt/media_rw/3664-6132/Android/data/com.someapp.dev/files/
cd /storage/3664-6132/Android/data/com.someapp.dev/files/
```

Number `0` in both, `/data/user/0/` and `/storage/emulated/0/` paths, represents the first user in a multi-user device.

Don't confuse `/mnt/sdcard/` path with a real removable storage path because sometimes such path is device specific, so you will need to search it on the internet or extract it using some Java code. In my case it is `/mnt/media_rw/3664-6132/` path.

```fundamental
XML                     -->  Java Method                                -->  Path

<files-path/>           -->  getContext().getFilesDir()                 -->  /data/user/0/com.someapp.dev/files

<cache-path/>           -->  getContext().getCacheDir()                 -->  /data/user/0/com.someapp.dev/cache

<external-path/>        -->  Environment.getExternalStorageDirectory()  -->  /storage/emulated/0

<external-files-path/>  -->  getContext().getExternalFilesDir("")       -->  /storage/emulated/0/Android/data/com.someapp.dev/files

<external-cache-path/>  -->  getContext().getExternalCacheDir()         -->  /storage/emulated/0/Android/data/com.someapp.dev/cache

<external-media-path/>  -->  getContext().getExternalMediaDirs()        -->  /storage/emulated/0/Android/media/com.someapp.dev
                                                                             /storage/3664-6132/Android/media/com.someapp.dev
																   
-                       -->  getContext().getExternalFilesDirs("")      -->  /storage/emulated/0/Android/data/com.someapp.dev/files
                                                                             /storage/3664-6132/Android/data/com.someapp.dev/files
```

---

Tilde `~` is short for the root directory.

Download a file or directory from your Android device:

```fundamental
adb pull ~/somefile.txt ./

adb pull ~/somedir ./
```

Keep in mind that not all directories have the write and/or execute permission; regardless, you can always upload files to and execute from `/data/local/tmp/` directory.

Upload a file or directory to your Android device:

```fundamental
adb push somefile.txt /data/local/tmp/

adb push somedir /data/local/tmp/
```

Empty directories will not be uploaded.

### Bypassing Permission Denied

Download a file from your Android device:

```bash
adb shell su -c 'cat ~/somefile.txt' > somefile.txt

adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
```

Download a directory from your Android device:

```bash
dir="somedir"; IFS=$'\n'; for subdir in $(adb shell su -c "find \"${dir}\" -type d"); do mkdir -p ".${subdir}"; done; for file in $(adb shell su -c "find \"${dir}\" -type f"); do adb shell su -c "cat \"${file// /\\\ }\"" > ".${file}"; done;
```

Upload a file or directory to your Android device:

```bash
src="somefile.txt"; dst="/data/data/com.someapp.dev/"; tmp="/data/local/tmp/"; base=$(basename "${src}"); adb push "${src}" "${tmp}"; adb shell su -c "cp -r \"${tmp}${base}\" \"${dst}\" && rm -rf \"${tmp}${base}\""
```

## 2. Inspect an APK

### Pull an APK (base.apk)

```bash
adb shell pm list packages 'keyword' | cut -d ':' -f2

adb pull $(adb shell pm path com.someapp.dev | cut -d ':' -f2 | grep 'base.apk') ./
```

Pull an APK by specific keyword (one-liner):

```bash
keyword="keyword"; pkg=$(adb shell pm list packages "${keyword}" | head -n 1 | cut -d ':' -f2); adb pull $(adb shell pm path "${pkg}" | cut -d ':' -f2 | grep 'base.apk') ./
```

Decode an APK using [Apktool](#decode). You should now see the `decoded` directory.

## AndroidManifest.xml

Always inspect `decoded/AndroidManifest.xml` content for possible misconfigurations.

Things to look for in AndroidManifest.xml:

* `minSdkVersion`, `targetSDKVersion`, and `maxSdkVersion` - app should not support outdated and vulnerable Android releases,
* `debuggable="true"` - production app (i.e. build) should not be debuggable,
* `android:allowBackup="true"` - app should not backup any sensitive data,
* `networkSecurityConfig` - inspect network security configurations for SSL/TLS pinnings, whitelisted domains, and `cleartextTrafficPermitted="true"` inside `decoded/res/xml/` directory,
* `exported="true"` - enumerate exported activities, content providers, and broadcast receivers,
* `permission` - look for unused [custom] permissions, and permissions with weak [protection](https://developer.android.com/guide/topics/manifest/permission-element) (`protectionLevel`),
* etc.

---

Extract URL schemes from AndroidManifest.xml:

```bash
xmlstarlet sel -t -m "//activity/intent-filter/data[@android:scheme]" -v "@android:scheme" -n AndroidManifest.xml | sort -uf | tee url_schemes.txt
```

Extract URL schemes and corresponding hosts from AndroidManifest.xml:

```bash
xmlstarlet sel -t -m "//activity/intent-filter/data[@android:scheme and @android:host]" -v "concat(@android:scheme, '://', @android:host)" -n AndroidManifest.xml  | sort -uf | tee url_schemes_hosts.txt
```

Resolve all `@string` keys from AndroidManifest.xml as `key: value` pairs:

```bash
dir="decoded"; for key in $(grep -Poi '(?<="\@string\/).+?(?=\")' "${dir}/AndroidManifest.xml" | sort -u); do val=$(xmlstarlet sel -t -v "/resources/string[@name='${key}']" "${dir}/res/values/strings.xml"); echo "${key}: ${val}"; done
```

## strings.xml

Always inspect `decoded/res/values/strings.xml` for endpoints, sensitive data \[in Base64 encoding\], etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

## 3. Search for Files and Directories

Search for files and directories from the root directory:

```bash
find / -iname '*keyword*'
```

Search for files and directories in the app specific directories (run `env` in [Objection](#7-objection)):

```bash
cd /data/user/0/com.someapp.dev/

cd /storage/emulated/0/Android/data/com.someapp.dev/

cd /storage/emulated/0/Android/obb/com.someapp.dev/
```

If you want to download a whole directory from your Android device, see section [Download/Upload Files and Directories](#downloadupload-files-and-directories).

I preffer downloading the app specific directories, and then doing the [file inspection](#4-inspect-files) on my Kali Linux.

Search for files and directories from the current directory:

```bash
find . -iname '*keyword*'

for keyword in 'access' 'account' 'admin' 'card' 'cer' 'conf' 'cred' 'customer' 'email' 'history' 'info' 'json' 'jwt' 'key' 'kyc' 'log' 'otp' 'pass' 'pem' 'pin' 'plist' 'priv' 'refresh' 'salt' 'secret' 'seed' 'setting' 'sign' 'sql' 'token' 'transaction' 'transfer' 'tar' 'txt' 'user' 'zip' 'xml'; do find . -iname "*${keyword}*"; done
```

### SharedPreferences

Search for files and directories in [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences) insecure storage directory:

```bash
cd /data/user/0/com.someapp.dev/shared_prefs/
```

The files should not be world-readable (e.g. `-rw-rw-r--` is not good, and `-rw-rw----` is good):

```bash
ls /data/user/0/com.someapp.dev/shared_prefs/ -al
```

If the production build is [debuggable](https://developer.android.com/topic/security/risks/android-debuggable), it is possible to get the read access rights to the app specific directories as a low-privileged user by leveraging `run-as` command.

Download a file from SharedPreferences as non-root:

```bash
adb exec-out run-as com.someapp.dev cat /data/user/0/com.someapp.dev/shared_prefs/somefile.xml > somefile.xml
```

SharedPreferences is unencrypted and backed up by default, and as such, should not contain any sensitive data after user logs out - it should be cleared by calling [SharedPreferences.Editor.clear\(\)](https://developer.android.com/reference/android/content/SharedPreferences.Editor#clear()). It should also be excluded from backups by specifying [dataExtractionRules](https://developer.android.com/guide/topics/data/autobackup#include-exclude-android-12) inside app's AndroidManifest.xml.

## 4. Inspect Files

Inspect memory dumps, binaries, files inside [a decompiled APK](#9-decompile-an-apk), files inside the app specific directories, or any other files.

After you finish testing \[and logout\], don't forget to [download](#downloadupload-files-and-directories) the app specific directories and inspect all the files inside. Inspect what is new and what still persists after logout.

There will be some false positive results since the regular expressions are not perfect. I prefer to use `rabin2` over `strings` because it can read Unicode characters.

On your Android device, try to modify app's files to test the filesystem checksum validation, i.e. to test the file integrity validation.

### Single File

Search for hardcoded sensitive data:

```bash
rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:basic|bearer)\ .+'

rabin2 -zzzqq somefile | grep -Pi '(?:access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)[\w\d]*(?:\"\ *\:|\ *\=).+'

rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:bug|comment|fix|issue|note|problem|to(?:\_|\ |)do|work)[^\w\d\n]+.+'
```

Extract URLs, deeplinks, IPs, etc.:

```bash
rabin2 -zzzqq somefile | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | sort -uf | tee urls.txt

rabin2 -zzzqq somefile | grep -Po '(?:\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
rabin2 -zzzqq somefile | sort -uf > strings.txt

grep -Po '(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}\=|[a-zA-Z0-9\+\/]{2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### Multiple Files

Search for hardcoded sensitive data:

```bash
IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '[^\w\d\n]+(?:basic|bearer)\ .+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '(?:access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)[\w\d]*(?:\"\ *\:|\ *\=).+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '[^\w\d\n]+(?:bug|comment|fix|issue|note|problem|to(?:\_|\ |)do|work)[^\w\d\n]+.+'; done
```

Extract URLs, deeplinks, IPs, etc.:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | grep -Piv '\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)' | sort -uf | tee urls.txt

IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '(?:\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | sort -uf > strings.txt

grep -Po '(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}\=|[a-zA-Z0-9\+\/]{2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### File Scraper

Automate all of the above file inspection (and more) with a single tool, also using multithreading.

```bash
apt-get -y install radare2

pip3 install file-scraper
```
  
```fundamental
file-scraper -dir source -o results.html -e default
```

More about my other project at [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

### SQLite 3

Use [ADB](#downloadupload-files-and-directories) to download database files, and then open them using [DB Browser for SQLite](https://sqlitebrowser.org).

To inspect the content, navigate to `Browse Data` tab, expand `Table` dropdown menu, and select the desired table.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/sqlite.png" alt="SQLite"></p>

<p align="center">Figure 3 - DB Browser for SQLite</p>

---

To inspect and/or edit database files on your Android device directly, use [SQLite 3](#magisk-sqlite-3); [ADB](#android-debug-bridge-adb) to your Android device and run the following commands:

```sql
sqlite3 somefile

.dump

.tables

SELECT * FROM sometable;

.quit
```

### Nuclei

Download mobile Nuclei templates:

```fundamental
git clone https://github.com/optiv/mobile-nuclei-templates ~/mobile-nuclei-templates
```

Decode an APK using [Apktool](#decode).

Search for hardcoded sensitive data:

```bash
echo decoded | nuclei -t ~/mobile-nuclei-templates/Keys/ -o nuclei_keys_results.txt

cat nuclei_keys_results.txt | grep -Po '(?<=\]\ ).+' | sort -uf > nuclei_keys_results_sorted.txt

echo decoded | nuclei -t ~/mobile-nuclei-templates/Android/ -o nuclei_android_results.txt

cat nuclei_android_results.txt | grep -Po '(?<=\]\ ).+' | sort -uf > nuclei_android_results_sorted.txt
```

### Backups

Create a backup of the whole Android device:

```fundamental
adb backup -system -apk -shared -all -f backup.ab
```

Create a backup of a specific app:

```
adb backup -nosystem -noapk -noshared -f backup.ab com.someapp.dev
```

App should not backup any sensitive data.

Restore from a backup:

```fundamental
adb restore backup.ab
```

--

Download the latest [Android Backup Extrator](https://github.com/nelenkov/android-backup-extractor/releases), and repackage a backup to a browsable archive (TAR):

```fundamental
java -jar abe.jar unpack backup.ab backup.tar
```

You can try to tamper with a browsable archive (TAR) and repackage it back to a restorable format:

```fundamental
java -jar abe.jar pack backup.tar backup.ab
```

## 5. Deeplinks

Test [/.well-known/assetlinks.json](https://developer.android.com/training/app-links/verify-android-applinks) using [developers.google.com/digital-asset-links/tools/generator](https://developers.google.com/digital-asset-links/tools/generator).

Create an HTML template to manually test deeplinks:

```bash
mkdir android_deeplinks

# multiple URL schemes

for scheme in $(cat url_schemes.txt); do for url in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do if [[ ! -z $url ]]; then echo -n "<a href='${url}'>${url}</a>\n<br><br>\n" | tee -a "android_deeplinks/${scheme}_deeplinks.html"; fi; done; done

# single URL scheme

scheme="somescheme"; for string in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do echo -n "<a href='${string}'>${string}</a>\n<br><br>\n"; done | tee -a "android_deeplinks/${scheme}_deeplinks.html"

python3 -m http.server 9000 --directory android_deeplinks
```

For `url_schemes.txt` see section [AndroidManifest.xml](#androidmanifestxml), and for `urls.txt` see section [4. Inspect Files](#4-inspect-files).

---

Open a deeplink using ADB:

```
adb shell am start -W -a android.intent.action.VIEW -d "somescheme://com.someapp.dev/some_path?some_param=some_value"
```

---

Sometimes, deeplinks can bypass authentication, including biometrics.

## 6. Frida

Useful resources:

* [frida.re](https://frida.re/docs/home)
* [learnfrida.info](https://learnfrida.info)
* [codeshare.frida.re](https://codeshare.frida.re)
* [github.com/dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida)
* [github.com/interference-security/frida-scripts](https://github.com/interference-security/frida-scripts)
* [github.com/m0bilesecurity/Frida-Mobile-Scripts](https://github.com/m0bilesecurity/Frida-Mobile-Scripts)
* [github.com/WithSecureLabs/android-keystore-audit](https://github.com/WithSecureLabs/android-keystore-audit)

List processes:

```bash
frida-ps -Uai

frida-ps -Uai | grep -i 'keyword'
```

Get PID for a specified keyword:

```bash
frida-ps -Uai | grep -i 'keyword' | cut -d ' ' -f 1
```

Discover internal methods/calls:

```bash
frida-discover -U -f com.someapp.dev | tee frida_discover.txt
```

Trace internal methods/calls:

```bash
frida-trace -U -p 1337

frida-trace -U -p 1337 -i 'recv*' -i 'send*'
```

### Frida Scripts

Bypass SSL Pinning using [android-ssl-pinning-bypass-2](https://codeshare.frida.re/@ivan-sincek/android-ssl-pinning-bypass-2) script:

```fundamental
frida -U -no-pause -l android-ssl-pinning-bypass-2.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/android-ssl-pinning-bypass-2 -f com.someapp.dev
```

I prefer to use the built-in method in [Objection](#bypasses).

---

For this Frida script to work, you need to push your Burp Proxy or ZAP certificate to a specific location with the specific name `cacert.der`:

```fundamental
adb push cacert.der /data/local/tmp/cacert.der
```

Bypass SSL Pinning using [android-ssl-pinning-bypass](https://codeshare.frida.re/@ivan-sincek/android-ssl-pinning-bypass) script:

```fundamental
frida -U -no-pause -l android-ssl-pinning-bypass.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/android-ssl-pinning-bypass -f com.someapp.dev
```

I prefer to use the built-in method in [Objection](#bypasses).

---

Monitor all intent calls, including deeplinks, using [android-intent-monitor](https://codeshare.frida.re/@ivan-sincek/android-intent-monitor) script:

```fundamental
frida -U -no-pause -l android-intent-monitor.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/android-intent-monitor -f com.someapp.dev
```

## 7. Objection

Useful resources:

* [github.com/sensepost/objection](https://github.com/sensepost/objection)

Run:

```fundamental
objection -g com.someapp.dev explore
```

Run a [Frida](#6-frida) script in Objection:

```fundamental
import somescript.js

objection -g com.someapp.dev explore --startup-script somescript.js
```

Get environment variables:

```fundamental
env
```

List KeyStore:

```fundamental
android keystore list
```

Dump app's memory to a file:

```fundamental
memory dump all mem.dmp
```

Dump app's memory after e.g. 10 minutes of inactivity, then, check if sensitive data is still in the memory. See section [4. Inspect Files](#4-inspect-files).

**In case Objection detaches from the app, use the process ID to attach it back without restarting the app.**

Search app's memory directly:

```bash
memory search 'somestring' --string
```

List classes and methods:

```bash
android hooking list classes

android hooking search classes com.someapp.dev
android hooking search classes 'keyword'

android hooking list class_methods 'someclass'
android hooking search methods com.someapp.dev 'someclass'
```

Hook on a class or method:

```bash
android hooking watch class 'someclass'

android hooking watch class_method 'somemethod' --dump-args --dump-backtrace --dump-return
```

Change the method's return value:

```bash
android hooking set return_value 'somemethod' false
```

Monitor the clipboard:

```fundamental
android clipboard monitor
```

### Bypasses

Bypass a root detection:

```bash
android root disable --quiet

objection -g com.someapp.dev explore --startup-command 'android root disable --quiet'
```

---

Bypass SSL pinning:

```bash
android sslpinning disable --quiet

objection -g com.someapp.dev explore --startup-command 'android sslpinning disable --quiet'
```

Also, you can import [Frida](#frida-scripts) script.

## 8. Drozer

Connect to a remote agent:

```fundamental
drozer console connect --server 192.168.1.10
```

List modules and show module details:

```fundamental
list

run somemodule --help
```

---

List packages:

```fundamental
run app.package.list

run app.package.list -f 'keyword'

run app.package.backup

run app.package.debuggable
```

Show a package information:

```fundamental
run app.package.info -a com.someapp.dev
```

Show app's AndroidManifest.xml:

```fundamental
run app.package.manifest com.someapp.dev
```

In case Drozer did not fetch the whole manifest file, decode an APK using [Apktool](#decode) and inspect the file manually.

Show app's attack surface:

```fundamental
run app.package.attacksurface com.someapp.dev
```

### Activities

List exported and unexported activities and intent filters:

```fundamental
run app.activity.info -i -a com.someapp.dev

run app.activity.info -u -i -a com.someapp.dev
```

Start an activity:

```fundamental
run app.activity.start --help

run app.activity.start --component com.someapp.dev com.someapp.dev.SomeActivity

run app.activity.start --component com.someapp.dev com.someapp.dev.SomeActivity --action android.intent.action.SOMEACTION --data-uri somescheme://somehost --extra string someKey someValue
```

Drozer is not able to pass arrays, lists, objects, etc. to intent filters due to console interface limitations.

### Providers

List exported and unexported content providers:

```fundamental
run app.provider.info -a com.someapp.dev

run app.provider.info -u -a com.someapp.dev
```

List, try to query, and do a vulnerability scan for all content providers' URIs:

```fundamental
run app.provider.finduri com.someapp.dev

run scanner.provider.finduris -a com.someapp.dev

run scanner.provider.injection -a com.someapp.dev

run scanner.provider.sqltables -a com.someapp.dev

run scanner.provider.traversal -a com.someapp.dev
```

### Broadcast Receivers

List exported and unexported broadcast receivers:

```fundamental
run app.broadcast.info -a com.someapp.dev

run app.broadcast.info -u -a com.someapp.dev
```

To do.

## 9. Decompile an APK

Decompile an APK:

```bash
jadx --threads-count $(grep -c 'processor' /proc/cpuinfo) -d /root/Desktop/source/ /root/Desktop/base.apk
```

**`d2j-dex2jar` \+ `jadx` actually gives the best results.**

Convert an APK to a JAR:

```fundamental
d2j-dex2jar base.apk -o base.jar
```

Decompile a JAR:

```bash
jadx --threads-count $(grep -c 'processor' /proc/cpuinfo) -d /root/Desktop/source_jar/ /root/Desktop/base.jar
```

Decompiling a JAR will give you a different directory structure, so you might want to decompile both, base.jar and base.apk.

Make sure to specify a full path to the output directory; otherwise, it will default to `/usr/share/jadx/bin/` directory (i.e. to the root directory).

Make sure to specify a full path to the base.jar or [base.apk](#pull-an-apk-baseapk); otherwise, JADX might not recognize it.

To inspect the source code using GUI, run the following command and open either base.jar or base.apk:

```fundamental
jadx-gui
```

---

Resolve `java.lang.OutOfMemoryError` issue by modifying `/usr/bin/d2j-dex2jar` and increasing the heap size specified in `-Xms` and `-Xmx` parameters, for example:

```fundamental
java -Xms1024m -Xmx4096m -classpath "${_classpath}" "com.googlecode.dex2jar.tools.Dex2jarCmd" "$@"
```

## 10. Repackage an APK

Sometimes, for some reason, [MobSF](#mobile-security-framework-mobsf) might not want to parse your APK; in that case, try to decode and repackage your APK, then, upload it again.

### Decode

Get the SMALI source code from an APK. Convenient for quickly fetching and inspecting app's AndroidManifest.xml.

```fundamental
apktool decode base.apk -o decoded
```

---

Decode an APK without decoding the sources and resources:

```fundamental
apktool decode -r -s base.apk -o decoded
```

### Repackage

Create a repackaged APK from the decoded directory:

```fundamental
apktool build -f decoded -o repackaged.apk
```

ZIP align all the files inside the repackaged APK:

```fundamental
zipalign -v 4 repackaged.apk
```

### Code Sign

Generate a code signing certificate:

```fundamental
keytool -genkey -keyalg RSA -validity 365 -keysize 2048 -storetype PKCS12 -alias apk_rsa_priv -keystore apk_rsa_priv.key -storepass 12345678
```

Code sign the repackaged APK:

```fundamental
jarsigner -sigalg SHA256withRSA -digestalg SHA-256 -tsa http://timestamp.digicert.com -keystore apk_rsa_priv.key -storepass 12345678 repackaged.apk apk_rsa_priv
```

Verify the repackaged APK's code signature:

```fundamental
jarsigner -verify -certs repackaged.apk
```

## 11. Miscellaneous

### Monitor the System Log

On your Kali Linux, run the following command:

```fundamental
adb logcat | grep 1337
```

Or, get the PID from a keyword:

```fundamental
keyword="keyword"; adb logcat | grep $(frida-ps -Uai | grep -i "${keyword}" | tr -s '[:blank:]' ' ' | cut -d ' ' -f 1)
```

### Monitor File Changes

On your Kali Linux, download the latest `fsmon` version from [GitHub](https://github.com/nowsecure/fsmon/releases), upload it to your Android device, give it necessary permissions, and run it:

```bash
adb push fsmon-and-arm /data/local/tmp/

adb shell su

chmod +x /data/local/tmp/fsmon-and-arm

/data/local/tmp/fsmon-and-arm /data/data/com.someapp.dev/
```

Always look for created or cached files, images/screenshots, etc.

Sensitive files such as know your customer (KYC) and similar, should not persists in the app specific directories on the user device after the file upload.

Images/screenshots path:

```fundamental
cd /mnt/sdcard/DCIM/
cd /storage/emulated/0/DCIM/

cd /mnt/media_rw/3664-6132/DCIM/
cd /storage/3664-6132/DCIM/
```

## 12. Tips and Security Best Practices

Bypass any keyboard restriction by copying and pasting data into an input field.

Access tokens should be short lived, and if possible, invalidated on logout.

Don't forget to test widgets, push notifications, and Firebase.

Sometimes, deeplinks and widgets can bypass authentication, including biometrics.

Only if explicitly allowed, try flooding 3rd party APIs to cause possible monetary damage to the company, or denial-of-service (DoS) by exhausting the allowed quotas/limits.

---

App should not disclose sensitive data in the predictive text (due to incorrectly defined input field type), app switcher, and push notifications.

App should warn a user when taking a screenshot of sensitive data.

App should warn a user that it is trivial to bypass biometrics authentication if Android device is jailbroken.

Production app (i.e. build) should not be debuggable.

## 13. Useful Websites and Tools

* [developer.android.com](https://developer.android.com) (official Android documentation)
* [streaak/keyhacks](https://github.com/streaak/keyhacks) (validate various API keys)
* [zxing.org/w/decode.jspx](https://zxing.org/w/decode.jspx) (decode QR codes)
* [odinforum.com](https://odinforum.com/discussion/11/latest-versions-of-odin-flashing-tool) (firmware flashing tool for Samsung devices)
* [samfrew.com](https://samfrew.com/) (firmwares for Samsung devices)
* [xdaforums.com](https://xdaforums.com/t/magisk-the-magic-mask-for-android.3473445) (mobile software development forum)
