/*
 * to cope with the following case (MacOSX 10.2)
 *  ... with CFLAGS=-x c++
 *  ... without CC=g++
 *  ... without LDFLAGS=-lstdc++
 * to avoid
 *  ... undefined reference to `__gxx_personality_v0'
 */
int __gxx_personality_v0;
