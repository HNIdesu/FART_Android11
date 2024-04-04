//Original:
//typed by hanbingle,just for fun!!
//email:edunwu@gmail.com
//只是对Android 8 版本进行了测试，其他版本请自行移植
/*使用说明
首先拷贝fart.so和fart64.so到/data/app目录下，并使用chmod 777 设置好权限,然后就可以使用了。
该frida版fart是利用反射的方式实现的函数粒度的脱壳，与使用hook方式实现的方法不同,可以使用spawn和attach两种方式使用。
使用方式1、以spawn方式启动app，等待app进入Activity界面后，执行fart()函数即可
使用方式2、app启动后，使用frida -U直接attach上进程，执行fart()函数即可
高级用法：可以调用dump(classname),传入要处理的类名，只完成对某一个类下的所有函数的CodeItem完成dump，效率更高，dump下来的类函数的所有CodeItem在含有类名的bin文件中。
* */

//Date: 2024-03-30
//Modified by HNIdesu
//Support: Android 11 arm/arm64
//Comment: 该脚本导出CodeItem效果更好
//Changes:
//1.优化了代码。
//2.将CodeItem改为json格式。
//3.支持Android11（其他Android版本需要自行修改）。

const saveDirectory = "/sdcard/Android/data/com.xxxx.tanke/files"

var funcGetDexFile = null
var addrGetObsoleteDexCache = null
var funcGetCodeItemLength = null
var funcBase64_encode = null
var funcFreePtr = null

function DexFile(start, size) {
    this.start = start
    this.size = size
}

function ArtMethod(dexfile, artmethodptr) {
    this.dexfile = dexfile
    this.artmethodptr = artmethodptr
}

function dumpCodeItem(className,methodName, artMethod, fileFlag) {
	console.log("dump code item of method: "+className+"->"+methodName+"\r\n")
    if (artMethod) {
        const dexFile = artMethod.dexfile
        const dexFileAddress = dexFile.start
        const dexFileSize = dexFile.size
        const dexFilePath =`${saveDirectory}/${dexFileSize}_${Process.getCurrentThreadId()}.dex`
        try {
            const file = new File(dexFilePath, "r")
            if (file) 
                file.close()
        } catch (e) {
            const file = new File(dexFilePath, "a+")
            if (file) {
                const dex_buffer = ptr(dexFileAddress).readByteArray(dexFileSize)
                file.write(dex_buffer)
                file.close()
                console.log(`dump dex ${dexFilePath}`)
            }
        }
        const pArtMethod = artMethod.artmethodptr
        const dexCodeItemOffset = Memory.readU32(ptr(pArtMethod).add(8))
        const dexMethodIndex = Memory.readU32(ptr(pArtMethod).add(12))
        if (dexCodeItemOffset && dexCodeItemOffset > 0) {
            const filePath =`${saveDirectory}/${dexFileSize}_${Process.getCurrentThreadId()}_${fileFlag}.json`
            const file = new File(filePath, "a+")
            if (file) {
                const codeItemAddress = ptr(dexFileAddress).add(dexCodeItemOffset)
                const codeItemLength = funcGetCodeItemLength(ptr(codeItemAddress))
                if (codeItemLength && codeItemLength > 0) {
                    Memory.protect(ptr(codeItemAddress), codeItemLength, 'rwx')
                    const pBase64Pength = Memory.alloc(8)
                    pBase64Pength.writeU64(0)
                    const pBase64Content = funcBase64_encode(ptr(codeItemAddress), codeItemLength, ptr(pBase64Pength))
                    const base64Content = ptr(pBase64Content).readCString(pBase64Pength.readU64())
                    funcFreePtr(ptr(pBase64Content))
					const content={
                        classname:className,
                        method_idx:dexMethodIndex,
                        code_item_len:codeItemLength,
                        data:base64Content
                    } 
                    file.write(JSON.stringify(content)+"\r\n")
                    file.close()
                }
            } else
                console.log("open file failed,filepath:", filePath)
        }
    }

}

function initModule() {
    console.log("go into init," + "Process.arch:" + Process.arch)
    let fartModule = null
    if (Process.arch === "arm64")
        fartModule = Module.load("/data/app/fart64.so")
    else if (Process.arch === "arm") 
        fartModule = Module.load("/data/app/fart.so")
    if (fartModule) {
        const addrGetDexFile = fartModule.findExportByName("GetDexFile")
        funcGetDexFile = new NativeFunction(addrGetDexFile, "pointer", ["pointer", "pointer"])
        const addrGetCodeItemLength = fartModule.findExportByName("GetCodeItemLength")
        funcGetCodeItemLength = new NativeFunction(addrGetCodeItemLength, "int", ["pointer"])
        const addrBase64_encode = fartModule.findExportByName("Base64_encode")
        funcBase64_encode = new NativeFunction(addrBase64_encode, "pointer", ["pointer", "int", "pointer"])
        const addrFreeptr = fartModule.findExportByName("Freeptr")
        funcFreePtr = new NativeFunction(addrFreeptr, "void", ["pointer"])
    }
    for (const symbol of Module.enumerateSymbolsSync("libart.so")) {
        if (symbol.name.indexOf("ArtMethod") >= 0 && symbol.name.indexOf("GetObsoleteDexCache") >= 0) {
            addrGetObsoleteDexCache = symbol.address
            break
        }
    }
}

function dealWithMethod(className, method) {
	try{
		console.log("start deal with method:" + className + "->" + method.toString())
		const artMethodPtr = Java.vm.getEnv().fromReflectedMethod(ptr(parseInt(method.$l.handle)))
		const dexFilePtr = funcGetDexFile(ptr(artMethodPtr), ptr(addrGetObsoleteDexCache))
		if (dexFilePtr) {
			const dexFileBegin = Memory.readPointer(ptr(dexFilePtr).add(Process.pointerSize * 1))
			const dexFileSize = Memory.readU32(ptr(dexFilePtr).add(Process.pointerSize * 2))
			const dexFile = new DexFile(dexFileBegin, dexFileSize)
			if (artMethodPtr) {
				const artMethod = new ArtMethod(dexFile, artMethodPtr)
				dumpCodeItem(className,method.toString(), artMethod, 'all')
			}
		}else
			console.log("dump method failed!")
	}catch(e){
		console.error(e)
	}
	
}

function dumpMethod(className, method) {
    console.log("start dump method:" + className + "->" + method.toString())
	const artMethodPtr = method.getArtMethod()
	const dexFilePtr = funcGetDexFile(ptr(artMethodPtr), ptr(addrGetObsoleteDexCache))
	console.log("DexPtr:"+dexFilePtr+"	"+"ArtPtr:"+artMethodPtr)
    if (dexFilePtr) {
        const dexFileBegin = Memory.readPointer(ptr(dexFilePtr).add(Process.pointerSize * 1))
        const dexFileSize = Memory.readU32(ptr(dexFilePtr).add(Process.pointerSize * 2))
        const dexFile = new DexFile(dexFileBegin, dexFileSize)
        if (artMethodPtr) {
            const artMethod = new ArtMethod(dexFile, artMethodPtr)
            dumpCodeItem(className,method.toString(), artMethod, className)
		}	
    }else
		console.log("dump method failed!")
}

//导出类的全部方法
function dumpClass(className) {
    if (Java.available) {
        Java.perform(function () {
            console.log("go into enumerate classloaders!")
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
					dumpClass(className,loader)
                },
                onComplete: function () {}
            })
        })
    }
}

//利用已有的classloader导出类的全部方法
function dumpClass(className,classLoader) {
    if (Java.available) {
        Java.perform(function () {
            let loadclass
			try {
				loadclass = classLoader.loadClass(className)
			} catch (e) {
				console.log(e)
				return
			}
            console.log(`load class ${className} succeed!`)
			try{
				let methods = loadclass.getDeclaredConstructors()
				for (const methodName in methods) {
					if(methodName.indexOf("$")!=0)//过滤掉非本类中的成员
						dumpMethod(className, methods[methodName])
				}
				methods = loadclass.getDeclaredMethods()	
				for (const methodName in methods) {
					if(methodName.indexOf("$")!=0)//过滤掉非本类中的成员
						dumpMethod(className, methods[methodName])
				}
			}catch(e){
				console.log(`Enumerate class ${className}'s methods failed.error:${e}`)
			}
		})
    }
}

function dealWithClassLoader(classLoader) {
    if (Java.available) {
        Java.perform(function () {
            try {
				console.log(`start deal with classloader:${classLoader}`)
                const DexFile = Java.use("dalvik.system.DexFile")
                const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader")
                const DexPathList = Java.use("dalvik.system.DexPathList")
                const DexPathList_Element = Java.use("dalvik.system.DexPathList$Element")

                const baseDexClassLoader = Java.cast(classLoader, BaseDexClassLoader)
                const pathList = Java.cast(baseDexClassLoader.pathList.value, DexPathList)
                const dexElements = pathList.dexElements.value
                for (const obj of dexElements) {
                    const element = Java.cast(obj, DexPathList_Element)
                    const dexFile = Java.cast(element.dexFile.value, DexFile)
                    const enumeratorClassNames = dexFile.entries()
                    while (enumeratorClassNames.hasMoreElements()) {
                        const className = enumeratorClassNames.nextElement().toString()
                        console.log(`start load class ${className}`)
						let loadclass = classLoader.loadClass(className)
                        console.log(`after load class ${className}`)
						try{
							let methods = loadclass.getDeclaredConstructors()
							for (const methodName in methods) {
								if(methodName.indexOf("$")!=0)//过滤掉非本类中的成员
									dumpMethod(className, methods[methodName])
							}
							methods = loadclass.getDeclaredMethods()	
							for (const methodName in methods) {
								if(methodName.indexOf("$")!=0)//过滤掉非本类中的成员
									dumpMethod(className, methods[methodName])
							}
						}catch(e){
							console.log(`Enumerate class ${className}'s methods failed.error:${e}`)
						}
                        
                    }
                }
            } catch (e) {
                console.log(e)
            }

        })
    }
}

function fart() {
    if (Java.available) {
        Java.perform(function () {
            console.log("start to enumerate classloaders!")
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    if (loader.toString().indexOf("BootClassLoader") ==-1) {
                        try {
                            dealWithClassLoader(loader)
                        } catch (e) {
                            console.log(`deal with classloader failed,error:${e}`)
                        }
                    } 
                },
                onComplete: function () {
                    console.log("find classloader instance over")
                }
            })
        })
    }
}

setImmediate(initModule)
/*
const Application=Java.use("android.app.Application");
var AppContext;
Application["getApplicationContext"].implementation=function(){
    if(!AppContext){
        AppContext=this.getApplicationContext()
        dumpClass("com.xxxx.tanke.activities.BeforeLoginActivity",AppContext.getClassLoader())
        return AppContext
    }else
        return this.getApplicationContext()
}*/

