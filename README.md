# auther
### a password manager lib

#### **auther may not be very cryptographically secure, so**
#### **help getting this right would be greatly appreciated**

## parsing from files:

example file:
```toml
[[passwords]]
type = "plain"
pass = "abc123"

[[passwords.location]]
name = "example.com"
email = "user@example.com"
username = "user"

[[passwords]]
type = "hash"
pass = "33cc8b1e74bde1aa2008f415782c51d933bad19dc9bbca15ff3a594ba13c351a421d97942a6395f5aa07e5116a9e744650684dbcac1250701f2823cc20fea649"
salt = "9b96947183bcfa788c7ec0c8b4d3fa2c7ef686d7b29434a3a99e9cbcc65c4d2328c8e2cca57fbc4f21c1dc262bcd8129cbeba5a65158e948a03ea3a2778c8cec"

[[passwords.location]]
name = "example.net"
username = "user"

[[passwords]]
type = "encrypted"
pass = "10150643464a"
```