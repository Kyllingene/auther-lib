# auther
### a password manager lib

#### **auther is not very cryptographically secure, so**
#### **help with getting this right would be very appreciated**

## parsing from files:

example file:
```toml
passwords = [
    # plain password with one full location
    { type = "plain", pass = "abc123", location = [{name = "example.com", username = "user", email = "user@example.com"}] },

    # hashed password with one location and user
    { type = "hash", pass = "c70b5dd9ebfb6f51d09d4132b7170c9d20750a7852f00680f65658f0310e810056e6763c34c9a00b0e940076f54495c169fc2302cceb312039271c43469507dc", location = [{name = "example.net", username = "user"}] },

    # encrypted password with no associated data
    { type = "encrypted", pass = [16, 21, 6, 67, 70, 74] }
]
```