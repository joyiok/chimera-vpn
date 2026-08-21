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
        return normalizeHandle(result, "start")
    }

    /** TCP/UDP + 端口跳跃；旧 AAR 没有此方法时会抛出 NoSuchMethodException。 */
    fun startTransportWithHop(
        seedHex: String,
        generation: Long,
        pskHex: String,
        serverAddr: String,
        transport: String,
        hopCount: Int,
        hopSpread: Int
    ): Long {
        val result = invokeStatic(
            "startTransportWithHop",
            seedHex, generation, pskHex, serverAddr, transport, hopCount.toLong(), hopSpread.toLong()
        )
        return normalizeHandle(result, "startTransportWithHop")
    }

    /** TCP/UDP 传输选择；旧 AAR 没有此方法时会抛出 NoSuchMethodException。 */
    fun startTransport(
        seedHex: String,
        generation: Long,
        pskHex: String,
        serverAddr: String,
        transport: String
    ): Long {
        val result = invokeStatic("startTransport", seedHex, generation, pskHex, serverAddr, transport)
        return normalizeHandle(result, "startTransport")
    }

    private fun normalizeHandle(result: Any?, method: String): Long = when (result) {
        is Long -> result
        is Int -> result.toLong()
        is Number -> result.toLong()
        null -> throw IllegalStateException("GoBind.$method 返回 null")
        else -> throw IllegalStateException("GoBind.$method 返回类型异常: ${result.javaClass.name}")
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

    fun socketFD(handle: Long): Int {
        val result = invokeStatic("socketFD", handle)
        return when (result) {
            is Int -> result.toInt()
            is Long -> result.toInt()
            is Number -> result.toInt()
            null -> -1
            else -> throw IllegalStateException("GoBind.socketFD 返回类型异常: ${result.javaClass.name}")
        }
    }

    /** Inbound silence in milliseconds. Missing on older AARs → 0. */
    fun idleMillis(handle: Long): Long = longMethod("idleMillis", handle)

    /** TUN payload bytes. Missing on older AARs → 0. */
    fun bytesSent(handle: Long): Long = longMethod("bytesSent", handle)

    fun bytesRecv(handle: Long): Long = longMethod("bytesRecv", handle)

    private fun longMethod(name: String, handle: Long): Long {
        if (handle < 0L) return 0L
        return try {
            val result = invokeStatic(name, handle)
            when (result) {
                is Long -> result
                is Int -> result.toLong()
                is Number -> result.toLong()
                else -> 0L
            }
        } catch (_: Throwable) {
            0L
        }
    }

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
