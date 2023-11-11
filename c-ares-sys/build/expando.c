#include <ares_version.h>

#define VERSION2(a, b, c) RUST_VERSION_C_ARES_##a##_##b##_##c
#define VERSION(a, b, c) VERSION2(a, b, c)

VERSION(ARES_VERSION_MAJOR, ARES_VERSION_MINOR, ARES_VERSION_PATCH)

