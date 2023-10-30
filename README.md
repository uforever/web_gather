# web_gather

## 编译

```
cargo build --color=always --message-format=json-diagnostic-rendered-ansi --package web_gather --bin web_gather --release
```

## 交叉编译

```
cross build --color=always --package web_gather --bin web_gather --release --target x86_64-unknown-linux-musl
```