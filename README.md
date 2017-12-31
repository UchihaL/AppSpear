# AppSpear

AppSpear is a universal and automated unpacking system suitable for both Dalvik and ART.
It can solve most mainstream Android packers, such Alibaba, Baidu, Bangcle, Ijiami, Qihoo360, Naga, NetQin, LIAPP, and so on.

AppSpear is based on Android runtime, we implemant it on Android OS 4.4.2 (Dalvik) and 5.0.1 (ART).
You can replace src/dalvik in AOSP 4.4.2 with src/Dalvik_Version 
or replace src/art in AOSP 5.0.1 with src/ART_Version

You can also replace /system/lib/libdvm.so in Android OS 4.4.2 with out/libdvm(AppSpear).so
or replace /system/lib/libart.so in Android OS 5.0.1 with out/libart(AppSpear).so

### Usage:

config file:
class.dlist: unpack entry point class
unpack.dlist: unpack entry point method
flag.dlist: 111001 (used for function control)

Push config files (samples in /sample) into data/data/(pkgname) file path then start app.
If you have any question, please contact me via emails to uchihalbd@gmail.com
