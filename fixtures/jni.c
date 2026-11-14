/* A native method that uses its JNIEnv the way libnative.so does.
 *
 * No jni.h on purpose: the fixture must build wherever a C compiler exists,
 * and the point being tested is the table layout, which jni.h only hides.
 * `env->functions[i]` is the same load the real headers compile to.
 *
 * Returns a bitmask of what went wrong, so zero means every call behaved.
 */
#include <string.h>

typedef struct JNIEnv JNIEnv;
typedef void *jobject;
typedef void *jclass;
typedef void *jmethodID;
typedef void *jstring;
typedef void *JavaVM;

struct JNIEnv {
    const void **functions;
};

/* Slot numbers from the JNI specification, in JNINativeInterface order. */
#define SLOT_GET_VERSION 4
#define SLOT_FIND_CLASS 6
#define SLOT_IS_SAME_OBJECT 24
#define SLOT_GET_METHOD_ID 33
#define SLOT_NEW_STRING_UTF 167
#define SLOT_GET_STRING_UTF_LENGTH 168
#define SLOT_GET_STRING_UTF_CHARS 169
#define SLOT_REGISTER_NATIVES 215
#define SLOT_GET_JAVA_VM 219
#define SLOT_EXCEPTION_CHECK 228

#define CALL(index, type) ((type)(env->functions[index]))

int jni_probe(JNIEnv *env) {
    if (!env || !env->functions) return 0x100;
    int score = 0;

    int version = CALL(SLOT_GET_VERSION, int (*)(JNIEnv *))(env);
    if (version != 0x00010006) score |= 1;

    jclass cls = CALL(SLOT_FIND_CLASS, jclass (*)(JNIEnv *, const char *))
        (env, "java/lang/String");
    if (!cls) score |= 2;

    jmethodID length = CALL(SLOT_GET_METHOD_ID,
                            jmethodID (*)(JNIEnv *, jclass, const char *, const char *))
        (env, cls ? cls : (jclass)1, "length", "()I");
    if (!length) score |= 4;

    /* The round trip is the part a licence check stands on: a string that
     * comes back different would fail a comparison the real VM would pass. */
    jstring text = CALL(SLOT_NEW_STRING_UTF, jstring (*)(JNIEnv *, const char *))
        (env, "s3cret");
    if (!text) score |= 8;

    const char *chars = CALL(SLOT_GET_STRING_UTF_CHARS,
                             const char *(*)(JNIEnv *, jstring, unsigned char *))
        (env, text ? text : (jstring)1, 0);
    if (!chars || strcmp(chars, "s3cret") != 0) score |= 16;

    int len = CALL(SLOT_GET_STRING_UTF_LENGTH, int (*)(JNIEnv *, jstring))
        (env, text ? text : (jstring)1);
    if (len != 6) score |= 32;

    if (CALL(SLOT_EXCEPTION_CHECK, unsigned char (*)(JNIEnv *))(env) != 0) score |= 64;

    if (CALL(SLOT_REGISTER_NATIVES,
             int (*)(JNIEnv *, jclass, const void *, int))
            (env, cls ? cls : (jclass)1, 0, 0) != 0)
        score |= 128;

    JavaVM *vm = 0;
    if (CALL(SLOT_GET_JAVA_VM, int (*)(JNIEnv *, JavaVM **))(env, &vm) != 0 || !vm)
        score |= 256;

    int same = CALL(SLOT_IS_SAME_OBJECT, int (*)(JNIEnv *, jobject, jobject))
        (env, cls ? cls : (jclass)1, cls ? cls : (jclass)1);
    if (same != 1) score |= 512;

    return score;
}

/* The name a real native library would export, so that `emulate` can put the
 * environment in place without being told to. */
int Java_com_example_Foo_probe(JNIEnv *env) {
    return jni_probe(env);
}
