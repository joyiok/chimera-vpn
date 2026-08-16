package com.chimera.vpn

import android.util.Log
import java.lang.reflect.InvocationTargetException

/**
 * gomobile 生成的 AAR 中，包 chimera/bind 会绑定为 Java 类 bind.Bind。
 * 在 bind.aar 尚未构建时，本对象通过反射加载该类；加载失败时给出明确错误，
 * 使 Android 工程在 Go 核心合并前也能正常编译。
 */
object GoBind {

    private const val TAG = "GoBind"
    private const val BIND_CLASS_NAME = "bind.Bind"
    private const val ERROR_NOT_BUILT = "Go core not built: run ./build-android-core.sh first"

    @Volatile
    private var bindClass: Class<*>? = null

    @Volatile
    private var loadAttempted = false

    private fun loadClass(): Class<*>? {
        val loaded = bindClass
        if (loaded != null) return loaded
        if (loadAttempted) return null
        loadAttempted = true
        return try {
            Class.forName(BIND_CLASS_NAME).also { bindClass = it }
        } catch (e: ClassNotFoundException) {
            Log.e(TAG, ERROR_NOT_BUILT, e)
            null
        } catch (e: LinkageError) {
            Log.e(TAG, "Go bind 类加载失败: ${e.message}")
            null
        }
    }

    fun isAvailable(): Boolean = loadClass() != null

    fun start(seedHex: String, generation: Long, pskHex: String, serverAddr: String): Long {
        val result = invokeStatic("start", seedHex, generation, pskHex, serverAddr)
        return when (result) {
            is Long -> result
            is Int -> result.toLong()
            is Number -> result.toLong()
            null -> throw IllegalStateException("GoBind.start 返回 null")
            else -> throw IllegalStateException("GoBind.start 返回类型异常: ${result.javaClass.name}")
        }
    }

    fun assignedIP(handle: Long): String? {
        val result = invokeStatic("assignedIP", handle)
        return result as? String
    }

    fun stop(handle: Long) {
        invokeStatic("stop", handle)
    }

    fun send(handle: Long, packet: ByteArray) {
        invokeStatic("send", handle, packet)
    }

    fun receive(handle: Long): ByteArray? = invokeStatic("receive", handle) as? ByteArray

    private fun invokeStatic(methodName: String, vararg args: Any?): Any? {
        val clazz = loadClass()
            ?: throw IllegalStateException(ERROR_NOT_BUILT)

        val method = clazz.methods.firstOrNull { candidate ->
            candidate.name.equals(methodName, ignoreCase = true) &&
                candidate.parameterCount == args.size
        } ?: throw NoSuchMethodException("$BIND_CLASS_NAME.$methodName (${args.size} 个参数)")

        return try {
            method.invoke(null, *args)
        } catch (e: InvocationTargetException) {
            throw e.targetException
        }
    }
}
