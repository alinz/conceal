# Conceal

Conceal is a tool to encrypt and decrypt `string` and `[]byte` fields in struct.

- Supports nested structures
- Supports array of structs field

# Usage

```bash
go get github.com/alinz/conceal
```

use struct's tags to identify id and fields that needs to be encrypted

```go
	type Class struct {
		Name string `conceal:"data"`
	}

	type User struct {
		ID      string   `conceal:"id"`
		Name    string   `conceal:"data"`
		Classes []*Class `conceal:"data"`
		Top     *Class   `conceal:"data"`
		Bytes   []byte   `conceal:"data"`
	}

	user := &User{
		ID:   "1",
		Name: "John",
		Classes: []*Class{
			{Name: "Cool"},
		},
		Top: &Class{
			Name: "Cool 2",
		},
		Bytes: []byte("hello world"),
  }
  
  cipher := // create your own cipher

  err := conceal.Encrypt(user, cipher)
  if err != nil {
    // handle error
  }


  err = conceal.Decrypt(user, cipher)
  if err != nil {
    // handle error
  }

```