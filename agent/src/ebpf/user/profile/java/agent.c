/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This file is compiled into agent.so, a shared library that will be injected
 * into the target Java process. After injection, it creates a symbol log file
 * into which each symbol is written.
 */

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include <jni.h>
#include <jvmti.h>
#include <jvmticmlr.h>

#include "../../config.h"
#include "config.h"

#define STRING_BUFFER_SIZE 2000
#define BIG_STRING_BUFFER_SIZE 20000

pthread_mutex_t g_df_lock;

FILE *perf_map_file_ptr = NULL;
FILE *perf_map_log_file_ptr = NULL;

int g_perf_map_file_size_limit;
int g_perf_map_file_size;

#define _(e)                                                                \
	if (e != JNI_OK) {                                                  \
		df_log("DF java agent failed, %s, error code: %d.", #e, e); \
		close_files();                                              \
		return e;                                                   \
	}

void df_log(const char *format, ...)
{
	if (perf_map_log_file_ptr) {
		va_list ap;
		va_start(ap, format);
		vfprintf(perf_map_log_file_ptr, format, ap);
		fprintf(perf_map_log_file_ptr, "\n");
		fflush(perf_map_log_file_ptr);
		va_end(ap);
	}
}

jint df_open_file(pid_t pid, const char *fmt, FILE ** ptr)
{
	FILE *file_ptr;
	char filename[50];	// Assuming the filename won't exceed 50 characters

	// Create the filename using snprintf
	snprintf(filename, sizeof(filename), fmt, pid);

	// Open the file for writing
	file_ptr = fopen(filename, "w");
	if (file_ptr == NULL) {
		fprintf(stderr, "Couldn't open %s: errno(%d)", filename, errno);
		return JNI_ERR;
	}

	*ptr = file_ptr;

	return JNI_OK;
}

jint open_perf_map_file(pid_t pid)
{
	return df_open_file(pid, PERF_MAP_FILE_FMT, &perf_map_file_ptr);
}

jint open_perf_map_log_file(pid_t pid)
{
	return df_open_file(pid, PERF_MAP_LOG_FILE_FMT, &perf_map_log_file_ptr);
}

jint close_files(void)
{
	if (perf_map_file_ptr)
		fclose(perf_map_file_ptr);

	if (perf_map_log_file_ptr)
		fclose(perf_map_log_file_ptr);

	return JNI_OK;
}

JNIEXPORT uint64_t df_java_agent_so_libs_test(void)
{
	/*
	 * This function is used during the attach phase to select which
	 * agent shared object libraries (GNU or musl libc) to use, using
	 * dlopen() and dlsym().
	 */
	return JAVA_AGENT_LIBS_TEST_FUN_RET_VAL;
}

jint get_jvmti_env(JavaVM * jvm, jvmtiEnv ** jvmti)
{
	if (jvm == NULL || jvmti == NULL) {
		return JNI_ERR;
	}

	jint error = (*jvm)->GetEnv(jvm, (void **)jvmti, JVMTI_VERSION_1_0);
	if (error != JNI_OK || *jvmti == NULL) {
		df_log("[error] Unable to access JVMTI.");
		return JNI_ERR;
	}
	return JNI_OK;
}

void jvmti_err_log(jvmtiEnv * jvmti, const jvmtiError err_num,
		   const char *help_msg_or_null)
{
	if (err_num == JVMTI_ERROR_NONE) {
		return;		// No need to log if there's no error
	}

	const char *err_name_str = "unknown";
	char *err_name_or_null;

	if ((*jvmti)->GetErrorName(jvmti, err_num, &err_name_or_null) ==
	    JVMTI_ERROR_NONE && err_name_or_null != NULL) {
		err_name_str = err_name_or_null;
	}

	const char *help_message =
	    (help_msg_or_null != NULL) ? help_msg_or_null : "";

	df_log("[error][%d] %s: %s.", err_num, err_name_str, help_message);
}

jint enable_capabilities(jvmtiEnv * jvmti)
{
	jvmtiCapabilities capabilities;
	memset(&capabilities, 0, sizeof(jvmtiCapabilities));

	capabilities.can_get_source_file_name = 1;
	capabilities.can_get_line_numbers = 1;
	capabilities.can_generate_compiled_method_load_events = 1;

	jvmtiError error = (*jvmti)->AddCapabilities(jvmti, &capabilities);
	if (error != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, error,
			      "Unable to get necessary JVMTI capabilities.");
		return JNI_ERR;
	}

	return JNI_OK;
}

void deallocate(jvmtiEnv * jvmti, void *string)
{
	if (string != NULL)
		(*jvmti)->Deallocate(jvmti, (unsigned char *)string);
}

void df_write_symbol(const void *code_addr, unsigned int code_size,
		     const char *entry)
{
	char symbol_str[1024];
	int bytes_all = 0;
	pthread_mutex_lock(&g_df_lock);
	snprintf(symbol_str, sizeof(symbol_str), "%lx %x %s\n",
		 (unsigned long)code_addr, code_size, entry);
	bytes_all = g_perf_map_file_size + strlen(symbol_str);
	if (bytes_all >= g_perf_map_file_size_limit) {
		pthread_mutex_unlock(&g_df_lock);
		return;
	}
	fprintf(perf_map_file_ptr, "%s", symbol_str);
	fflush(perf_map_file_ptr);
	g_perf_map_file_size = bytes_all;
	pthread_mutex_unlock(&g_df_lock);
}

void generate_single_entry(jvmtiEnv * jvmti,
			   jmethodID method, const void *code_addr,
			   jint code_size)
{
	jclass class;
	char *method_name = NULL;
	char *msig = NULL;
	char *csig = NULL;

	char output[STRING_BUFFER_SIZE];
	char source_info[1000] = "";
	char *method_signature = "";
	size_t noutput = sizeof(output);

	strncpy(output, "<error writing signature>", noutput);

	if ((*jvmti)->GetMethodName(jvmti, method, &method_name, &msig, NULL) ==
	    JVMTI_ERROR_NONE
	    && (*jvmti)->GetMethodDeclaringClass(jvmti, method,
						 &class) == JVMTI_ERROR_NONE
	    && (*jvmti)->GetClassSignature(jvmti, class, &csig,
					   NULL) == JVMTI_ERROR_NONE) {
		char class_name[STRING_BUFFER_SIZE];
		memset(class_name, 0, sizeof(class_name));
		if (strlen(csig) < sizeof(class_name)) {
			memcpy(class_name, csig, strlen(csig));
		} else {
			memcpy(class_name, csig, sizeof(class_name) - 1);
		}
		snprintf(output, noutput, "%s::%s%s%s", class_name,
			 method_name, method_signature, source_info);

		deallocate(jvmti, (unsigned char *)csig);
	}

	deallocate(jvmti, (unsigned char *)method_name);
	deallocate(jvmti, (unsigned char *)msig);

	df_write_symbol(code_addr, (unsigned int)code_size, output);
}

void JNICALL
cbCompiledMethodLoad(jvmtiEnv * jvmti,
		     jmethodID method,
		     jint code_size,
		     const void *code_addr,
		     jint map_length,
		     const jvmtiAddrLocationMap * map, const void *compile_info)
{
	generate_single_entry(jvmti, method, code_addr, code_size);
}

void JNICALL
cbDynamicCodeGenerated(jvmtiEnv * jvmti,
		       const char *name, const void *address, jint length)
{

	df_write_symbol(address, (unsigned int)length, name);
}

void JNICALL
cbCompiledMethodUnload(jvmtiEnv * jvmti, jmethodID method, const void *address)
{

	df_write_symbol(address, 0, "");
}

jvmtiError set_callback_funs(jvmtiEnv * jvmti)
{
	jvmtiEventCallbacks callbacks;

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.CompiledMethodLoad = &cbCompiledMethodLoad;
	callbacks.CompiledMethodUnload = &cbCompiledMethodUnload;
	callbacks.DynamicCodeGenerated = &cbDynamicCodeGenerated;

	jvmtiError err = (*jvmti)->SetEventCallbacks(jvmti, &callbacks,
						     (jint) sizeof(callbacks));
	if (err != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, err,
			      "Unable to attach CompiledMethodLoad callback.");
		return JNI_ERR;
	}

	return JNI_OK;
}

jint set_notification_modes(jvmtiEnv * jvmti, jvmtiEventMode mode)
{
	jvmtiError error;

	error =
	    (*jvmti)->SetEventNotificationMode(jvmti, mode,
					       JVMTI_EVENT_COMPILED_METHOD_LOAD,
					       NULL);
	if (error != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, error,
			      "Unable to set notification mode for CompiledMethodLoad.");
		return JNI_ERR;
	}

	error =
	    (*jvmti)->SetEventNotificationMode(jvmti, mode,
					       JVMTI_EVENT_COMPILED_METHOD_UNLOAD,
					       NULL);
	if (error != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, error,
			      "Unable to set notification mode for CompiledMethodUnload.");
		return JNI_ERR;
	}

	error =
	    (*jvmti)->SetEventNotificationMode(jvmti, mode,
					       JVMTI_EVENT_DYNAMIC_CODE_GENERATED,
					       NULL);
	if (error != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, error,
			      "Unable to set notification mode for DynamicCodeGenerated.");
		return JNI_ERR;
	}

	return JNI_OK;
}

jint replay_callbacks(jvmtiEnv * jvmti)
{
	jvmtiError error;
	jvmtiPhase phase;

	error = (*jvmti)->GetPhase(jvmti, &phase);
	if (error != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, error,
			      "replay_callbacks(): GetPhase() error.");
		return JNI_ERR;
	}

	if (phase != JVMTI_PHASE_LIVE) {
		df_log("Skipping replay_callbacks(), not in live phase.");
		return JNI_OK;
	}

	error =
	    (*jvmti)->GenerateEvents(jvmti, JVMTI_EVENT_DYNAMIC_CODE_GENERATED);
	if (error != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, error,
			      "GenerateEvents(JVMTI_EVENT_DYNAMIC_CODE_GENERATED).");
		return JNI_ERR;
	}

	error =
	    (*jvmti)->GenerateEvents(jvmti, JVMTI_EVENT_COMPILED_METHOD_LOAD);
	if (error != JVMTI_ERROR_NONE) {
		jvmti_err_log(jvmti, error,
			      "GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD).");
		return JNI_ERR;
	}

	return JNI_OK;
}

JNIEXPORT jint JNICALL
Agent_OnAttach(JavaVM * vm, char *options, void *reserved)
{
	jvmtiEnv *jvmti;
	pthread_mutex_init(&g_df_lock, NULL);
	_(open_perf_map_log_file(getpid()));
	df_log("- JVMTI agent write perf files max size %s bytes.", options);
	g_perf_map_file_size_limit = atoi(options);
	g_perf_map_file_size = 0;
	_(open_perf_map_file(getpid()));
	_(get_jvmti_env(vm, &jvmti));
	_(enable_capabilities(jvmti));
	_(set_callback_funs(jvmti));
	_(set_notification_modes(jvmti, JVMTI_ENABLE));
	_(replay_callbacks(jvmti));
	_(set_notification_modes(jvmti, JVMTI_DISABLE));

	df_log("- JVMTI symbolization agent startup sequence complete.");

	close_files();
	return 0;
}
