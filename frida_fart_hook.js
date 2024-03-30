//Original:
//typed by hanbingle,just for fun!!
//email:edunwu@gmail.com
//只是对Android 8 版本进行了测试，其他版本请自行移植
/*使用说明
首先拷贝fart.so和fart64.so到/data/app目录下，并使用chmod 777 设置好权限,然后就可以使用了。
该frida版fart是使用hook的方式实现的函数粒度的脱壳，仅仅是对类中的所有函数进行了加载，但依然可以解决绝大多数的抽取保护
需要以spawn方式启动app，等待app进入Activity界面后，执行fart()函数即可。如app包名为com.example.test,则
frida -U -f com.example.test -l frida_fart_hook.js --no-pause，然后等待app进入主界面,执行fart()
高级用法：如果发现某个类中的函数的CodeItem没有dump下来，可以调用dump(classname),传入要处理的类名，完成对该类下的所有函数体的dump,dump下来的函数体会追加到bin文件当中。
*/

//Date: 2024-03-29
//Modified by HNIdesu
//Support: Android 11 arm/arm64
//Changes:
//1.优化了代码。
//2.将CodeItem改为json格式。
//3.支持Android11（其他Android版本需要自行修改）。
 
var hasHookedLibart = false

//fart.so
var funcGetCodeItemLength = null
var funcBase64Encode = null
var funcFreeptr = null

var addrPrettyMethod=null

//fartutil.so
var funcGetArtMethodPrettyNameDelegate=null
var funcFreeArtMethodPrettyName=null


//最好为目标应用数据目录（/sdcard/Android/data/{package_name}/files或者/data/data/{package_name}/files），结尾不加'/'!
const saveDirectory = "/sdcard/Android/data/com.lptiyu.tanke/files"
const dexFileMap = {}
const artMethodMap = {}


//保存DexFile的地址和大小的类
function DexFile(start, size) {
    this.start = start
    this.size = size
}

//保存ArtMethod的dex文件和地址的类
function ArtMethod(dexfile, artmethodptr) {
    this.dexfile = dexfile
    this.artmethodptr = artmethodptr
}


function loadModules(){
    let moduleFart=null
    if (Process.arch == "arm64") 
        moduleFart = Module.load("/data/app/fart64.so")
    else if (Process.arch == "arm") 
        moduleFart = Module.load("/data/app/fart.so")
    if (moduleFart) {
        const addrGetCodeItemLength = moduleFart.findExportByName("GetCodeItemLength")
        funcGetCodeItemLength = new NativeFunction(addrGetCodeItemLength, "int", ["pointer"])
        const addrBase64Encode = moduleFart.findExportByName("Base64_encode")
        funcBase64Encode = new NativeFunction(addrBase64Encode, "pointer", ["pointer", "int", "pointer"])
        const addrFreeptr = moduleFart.findExportByName("Freeptr")
        funcFreeptr = new NativeFunction(addrFreeptr, "void", ["pointer"])
    }

    const moduleFartUtil=Module.load("/data/app/fartutil64.so")
    const addrGetArtMethodPrettyNameDelegate=moduleFartUtil.findExportByName("getArtMethodPrettyNameDelegate")
    const addrFreeArtMethodPrettyName=moduleFartUtil.findExportByName("freeArtMethodPrettyName")
    funcGetArtMethodPrettyNameDelegate=new NativeFunction(addrGetArtMethodPrettyNameDelegate,"pointer",["pointer","pointer"])
    funcFreeArtMethodPrettyName=new NativeFunction(addrFreeArtMethodPrettyName,"void",["pointer"])
}

//主要用于hook libart.so的LoadMethod方法，在该方法调用时导出dex文件和CodeItem数据
function hookArt() {
    if (hasHookedLibart)return
    const symbols = Module.enumerateSymbolsSync("libart.so")
    let addrLoadMethod=null
    let methodFindCount=2;
    for (let i = 0,count=symbols.length; i <count ; i++) {
        const symbol = symbols[i]
        if(symbol.name=="_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_13ClassAccessor6MethodENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE"){
            //不同安卓版本LoadMethod函数签名不同，需要根据实际情况修改。
            //Android 8： _ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE
		    //Android 11： _ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_13ClassAccessor6MethodENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE
            addrLoadMethod = symbol.address
            methodFindCount--
        }else if(symbol.name=="_ZN3art9ArtMethod12PrettyMethodEPS0_b"){//用于获取ArtMethod的类名
            //Android11: _ZN3art9ArtMethod12PrettyMethodEPS0_b
            addrPrettyMethod=symbol.address
            methodFindCount--
        }
        if(!methodFindCount)
            break
    }
    if(!addrLoadMethod)return
    Interceptor.attach(addrLoadMethod, {//hook LoadMethod方法
        onEnter: function (args) {
            this.dexfileptr = args[1]
            this.artmethodptr = args[4]
        },
        onLeave: function (_) {
            let dexFileAddress = 0
            let dexFileSize = 0
            if (this.dexfileptr) {
                dexFileAddress = Memory.readPointer(ptr(this.dexfileptr).add(Process.pointerSize * 1))
                dexFileSize = Memory.readU32(ptr(this.dexfileptr).add(Process.pointerSize * 2))
                const dexFilePath =`${saveDirectory}/${dexFileSize}_loadMethod.dex`
                try {
                    const file = new File(dexFilePath, "r")
                    if (file) file.close()
                } catch (e) {//如果文件不存在则将dex写入到文件
                    const file = new File(dexFilePath, "a+")
                    if (file) {
                        const dex_buffer = ptr(dexFileAddress).readByteArray(dexFileSize)
                        file.write(dex_buffer)
                        file.close()
                        console.log(`dump dex :${dexFilePath}`)
                    }
                }
            }
            const dexFile = new DexFile(dexFileAddress, dexFileSize)
            if (!dexFileMap[dexFileAddress]) {
                dexFileMap[dexFileAddress] = dexFileSize
                console.log("got a dex:", dexFileAddress, dexFileSize)
            }
            if (this.artmethodptr) {		
                const artMethod = new ArtMethod(dexFile, this.artmethodptr)
                if (!artMethodMap[this.artmethodptr])
                    artMethodMap[this.artmethodptr] = artMethod
            }
        }
    })
    hasHookedLibart = true
}

//导出CodeItem
function dumpCodeItem(artMethod) {
    if (artMethod) {
        const dexFile = artMethod.dexfile
        const dexFileAddress = dexFile.start
        const dexFileSize = dexFile.size
        const dexFileSavePath =`${saveDirectory}/${dexFileSize}_${Process.getCurrentThreadId()}.dex`
        try{
            const file= new File(dexFileSavePath, "r")
            if (file) 
                file.close()
        }catch(_){//如果dex文件不存在就创建并写入数据
            const file = new File(dexFileSavePath, "a+")
            if (file) {
                const dexBuffer = ptr(dexFileAddress).readByteArray(dexFileSize)
                file.write(dexBuffer)
                file.close()
                console.log(`dump dex: ${dexFileSavePath}`)
            }
        }
        const artmethodPtr = artMethod.artmethodptr
        const ptrPrettyMethod=funcGetArtMethodPrettyNameDelegate(addrPrettyMethod,artmethodPtr)
        const fullName=ptrPrettyMethod.readUtf8String()
        const className=fullName.substring(0,fullName.lastIndexOf("."))
        funcFreeArtMethodPrettyName(ptrPrettyMethod)
        const dexCodeItemOffset = Memory.readU32(ptr(artmethodPtr).add(8))
        const dexMethodIndex = Memory.readU32(ptr(artmethodPtr).add(12))
        if (dexCodeItemOffset && dexCodeItemOffset > 0) {
            const filePath=`${saveDirectory}/${dexFileSize}_${Process.getCurrentThreadId()}.json`
            const file = new File(filePath, "a+")
            if (file) {
                const codeItemStartAddress = ptr(dexFileAddress).add(dexCodeItemOffset)
                const codeItemLength = funcGetCodeItemLength(ptr(codeItemStartAddress))
                if (codeItemLength & codeItemLength > 0) {
					Memory.protect(ptr(codeItemStartAddress), codeItemLength, 'rwx')
					const pBase64Length = Memory.alloc(8)
                    pBase64Length.writeU64(0)
					const pBase64 = funcBase64Encode(ptr(codeItemStartAddress), codeItemLength, ptr(pBase64Length))
					const base64Content = ptr(pBase64).readCString(pBase64Length.readU64())					
					funcFreeptr(ptr(pBase64))
					const content={classname:className,method_idx:dexMethodIndex,offset:dexCodeItemOffset,code_item_len:codeItemLength,data:base64Content}
					file.write(JSON.stringify(content)+"\r\n")
					file.close()
                }
            } else 
                console.log("open file failed,filepath:", filePath)
        }
    }

}

//导出全部CodeItem
function dumpAll() {
    console.log("start dump all codeitems.......")
    try{
        for (const pArtMethod in artMethodMap)
            dumpCodeItem(artMethodMap[pArtMethod])
    }catch(_){}
    
    console.log("end dump all codeitems.......")
}


//枚举ClassLoader下的全部Dex的全部类并主动加载
function dealWithClassLoader(classLoader) {
    if (Java.available) {
        Java.perform(function () {
            try {
                const DexFile = Java.use("dalvik.system.DexFile")
                const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader")
                const DexPathList = Java.use("dalvik.system.DexPathList")
                const DexPathList_Element = Java.use("dalvik.system.DexPathList$Element")
                const baseDexClassloader = Java.cast(classLoader, BaseDexClassLoader)
                const dexElements = Java.cast(baseDexClassloader.pathList.value, DexPathList).dexElements.value
                if (dexElements != null) {
                    for (const obj of dexElements) {
                        const element = Java.cast(obj, DexPathList_Element)
                        const dexFile = Java.cast(element.dexFile.value, DexFile)
                        const classNameEnumerator = dexFile.entries()
                        while (classNameEnumerator.hasMoreElements()) {
                            const className = classNameEnumerator.nextElement().toString()
                            console.log("start loadclass->", className)
                            const loadclass = classLoader.loadClass(className)
                            console.log("after loadclass->", loadclass)
                        }
                    }
                }
            } catch (e) {
                console.log(e)
            }

        })
    }
}

//导出单个类的dex和CodeItem
function dumpclass(className) {
    if (Java.available) {
        Java.perform(function () {
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        console.log("start loadclass->", className)
                        const loadclass = loader.loadClass(className)
                        console.log("after loadclass->", loadclass)
                    } catch (_) {}
                },
                onComplete: function () {}
            })
        })
    }
}

//导出全部dex以及CodeItem
function fart() {
    if (Java.available) {
        Java.perform(function () {
            dumpAll()//利用被动调用进行函数粒度的dump，对app正常运行过程中自己加载的所有类函数进行dump
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        console.log(`start deal with classloader:${loader}`)
                        dealWithClassLoader(loader)
                    } catch (e) {
                        console.log(`deal with classloader error:${e}`)
                    }
                },
                onComplete: function () {}
            })
            dumpAll()//为对当前ClassLoader中的所有类进行主动加载，从而完成ArtMethod中的CodeItem的dump
        })
    }
}
setImmediate(()=>{
    loadModules()
    hookArt()
})
setTimeout(fart,1000)
