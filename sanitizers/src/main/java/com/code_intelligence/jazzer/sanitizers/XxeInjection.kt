// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.*
import com.fasterxml.jackson.databind.JsonNode
import java.io.IOException
import java.lang.invoke.MethodHandle
import java.net.ConnectException;


@Suppress("unused_parameter", "unused")
object XxeInjection {
    private const val XML_ENTITIY = "<!DOCTYPE jaz [ <!ENTITY % xxe SYSTEM \"http://0.0.0.0\"> %xxe; ]>";
    @MethodHooks(
        MethodHook(type = HookType.REPLACE, targetClassName = "com.fasterxml.jackson.databind.ObjectMapper", targetMethod = "readTree", targetMethodDescriptor = "(Ljava/lang/String;)Lcom/fasterxml/jackson/databind/JsonNode;"),
    )

    @JvmStatic
    fun checkXxe(method: MethodHandle, thisObject: Any?, arguments: Array<Any>, hookId: Int): Any {
        if (arguments.isNotEmpty() && arguments[0] is String) {
            val xml = arguments[0] as String
            Jazzer.guideTowardsContainment(xml, XML_ENTITIY, hookId)
        }

        try {
            return method.invokeWithArguments(thisObject, *arguments)
        } catch (e: IOException) {
            var cause: Throwable? = e
            while (cause != null) {
                if (cause.cause == null) {
                    break
                }

                if (cause.cause is ConnectException) {
                    Jazzer.reportFindingFromHook(
                        FuzzerSecurityIssueHigh(
                            """
                            XXE Injection
                            Injected query: ${arguments[0]}
                            ${e.message}
                            """.trimIndent()
                        )
                    )
                }

                cause = cause.cause;
            }

            throw e;
        }
    }
}