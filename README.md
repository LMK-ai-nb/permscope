# permscope

MoonBit library for parsing and auditing the `Permissions-Policy` HTTP response
header.

`permscope` helps small web tools, gateways, static-site checks, and CI scripts
answer three questions:

- Which browser capabilities does this header allow?
- Are sensitive features such as camera, microphone, geolocation, payment, USB,
  serial, HID, or Bluetooth too permissive?
- Can an old `Feature-Policy` header be migrated to modern
  `Permissions-Policy` syntax?

## Status

Initial August Hackathon version by 李明坤.

## Quick Start

```bash
moon test
moon run cmd/main
```

More usage examples are added with the implementation and tests.
