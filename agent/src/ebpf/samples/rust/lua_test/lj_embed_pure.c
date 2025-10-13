// lua_embed_pure.c
// Build against stock Lua 5.1–5.4 and exercise pcall/resume/yield paths.
//
// This program:
//   - opens standard libs (-> luaL_openlibs)
//   - luaL_loadfile + lua_pcall to load a factory function from a script
//   - calls the factory to get a coroutine (thread)
//   - repeatedly lua_resume's it (yield-heavy) with small sleeps for sampling
//   - deliberately uses pcall around a failing function to hit lua_pcall
//
// Compile (examples):
//   # Lua 5.4
//   cc -O2 -o lua_embed_pure lua_embed_pure.c $(pkg-config --cflags --libs lua5.4)
//   # Lua 5.3
//   cc -O2 -o lj_embed_pure lj_embed_pure.c $(pkg-config --cflags --libs lua5.3)
//   # Lua 5.1
//   cc -O2 -o lj_embed_pure lj_embed_pure.c $(pkg-config --cflags --libs lua5.1)
//
// Run:
//   ./lj_embed_pure ./test_pure.lua 100000
//
// Notes:
// - Your uprobe finder should detect liblua5.x.so in /proc/<pid>/maps.
// - Attach to: lua_pcall, lua_resume, and lua_yieldk (5.2+) and/or lua_yield (5.1).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#ifndef LUA_OK
#define LUA_OK 0
#endif

// ---- Version shims -------------------------------------------------

#ifndef LUA_VERSION_NUM
#error "LUA_VERSION_NUM not defined"
#endif

#if LUA_VERSION_NUM >= 504
    /* Lua 5.4+ */
    #define RESUME(L, FROM, N, NRES)  lua_resume((L), (FROM), (N), (NRES))
    #define PCALL(L, NARG, NRES, ERR) lua_pcallk((L), (NARG), (NRES), (ERR), 0, NULL)
    #define YIELD(L, NRES)            lua_yieldk((L), (NRES), 0, NULL)
#elif LUA_VERSION_NUM >= 502
    /* Lua 5.2, 5.3 */
    #define RESUME(L, FROM, N, NRES)  lua_resume((L), (FROM), (N)) /* NRES unused */
    #define PCALL(L, NARG, NRES, ERR) lua_pcallk((L), (NARG), (NRES), (ERR), 0, NULL)
    #define YIELD(L, NRES)            lua_yieldk((L), (NRES), 0, NULL)
#else
    /* Lua 5.1 */
    #define RESUME(L, FROM, N, NRES)  lua_resume((L), (N))  /* FROM, NRES unused */
    #define PCALL(L, NARG, NRES, ERR) lua_pcall((L), (NARG), (NRES), (ERR))
    #define YIELD(L, NRES)            lua_yield((L), (NRES))
#endif

static void die(lua_State *L, const char *msg) {
  const char *err = L ? lua_tostring(L, -1) : NULL;
  if (err) fprintf(stderr, "%s: %s\n", msg, err);
  else fprintf(stderr, "%s\n", msg);
  exit(1);
}

// A small C function we call via pcall to ensure we hit lua_pcall path.
// It optionally throws a Lua error to guarantee a non-happy pcall edge.
static int c_func_maybe_fail(lua_State *L) {
  int should_fail = lua_toboolean(L, 1);
  if (should_fail) {
    return luaL_error(L, "intentional error from C");
  }
  lua_pushliteral(L, "ok-from-c");
  return 1;
}

int main(int argc, char **argv) {
  const char *script = (argc > 1) ? argv[1] : "test_pure.lua";
  int iterations = (argc > 2) ? atoi(argv[2]) : 100000;

  lua_State *L = luaL_newstate();
  if (!L) die(NULL, "luaL_newstate failed");
  luaL_openlibs(L);

  // Register C function; Lua code can pcall it to hit lua_pcall hot path.
  lua_pushcfunction(L, c_func_maybe_fail);
  lua_setglobal(L, "c_func_maybe_fail");

  // Load script -> stack: [ factory_fn ]
  if (luaL_loadfile(L, script) != 0) die(L, "luaL_loadfile");
  if (lua_pcall(L, 0, 1, 0) != 0)   die(L, "lua_pcall (returning factory)");

  // Call factory with k (number of yields). Expect a coroutine (thread) back.
  lua_pushinteger(L, iterations);
  if (lua_pcall(L, 1, 1, 0) != 0)   die(L, "lua_pcall (factory call)");

  if (!lua_isthread(L, -1)) die(L, "factory did not return a coroutine");
  lua_State *Lco = lua_tothread(L, -1);

  // Extra: exercise lua_pcall with success and failure (fires uprobes).
  lua_getglobal(L, "pcall");
  lua_getglobal(L, "c_func_maybe_fail");
  lua_pushboolean(L, 0);
  if (lua_pcall(L, 2, 2, 0) != 0) die(L, "pcall(c_func_maybe_fail,false)");
  // pop results
  lua_pop(L, 2);

  lua_getglobal(L, "pcall");
  lua_getglobal(L, "c_func_maybe_fail");
  lua_pushboolean(L, 1); // cause error
  if (lua_pcall(L, 2, 2, 0) != 0) die(L, "pcall(c_func_maybe_fail,true)");
  // pop results
  lua_pop(L, 2);

  // Resume loop — hits lua_resume and coroutine.yield → lua_yield/lua_yieldk
  struct timespec ts = {0, 5 * 1000 * 1000}; // 5ms
  for (;;) {
    int nresults = 0;
    int status = RESUME(Lco, NULL, 0, &nresults);
    if (status == LUA_OK) {
      // finished
      break;
    }
#if LUA_VERSION_NUM >= 502
    else if (status == LUA_YIELD) {
#else
    else if (status == LUA_YIELD) {
#endif
      // yielded; sleep a bit to allow profiler sampling variety
      nanosleep(&ts, NULL);
      continue;
    } else {
      // error
      const char *err = lua_tostring(Lco, -1);
      fprintf(stderr, "resume error: %s\n", err ? err : "(unknown)");
      break;
    }
  }

  // Keep around a little to ensure samples are captured
  struct timespec tail = {0, 50 * 1000 * 1000}; // 50ms
  nanosleep(&tail, NULL);

  lua_close(L);
  return 0;
}